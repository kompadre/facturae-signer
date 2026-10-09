package main

import (
	"bufio"
	"context"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestParseListen(t *testing.T) {
	cases := []struct {
		in      string
		network string
		addr    string
		bad     bool
	}{
		{"", "tcp", ":8080", false},
		{":9000", "tcp", ":9000", false},
		{"tcp:127.0.0.1:8080", "tcp", "127.0.0.1:8080", false},
		{"vsock:9000", "vsock", "9000", false},
		{"vsock:banana", "", "", true},
		{"vsock:", "", "", true},
		{"tcp:", "", "", true},
		{"unix:/run/facturae-signer/signer.sock", "unix", "/run/facturae-signer/signer.sock", false},
		{"unix:", "", "", true},
	}
	for _, c := range cases {
		spec, err := parseListen(c.in)
		if c.bad {
			if err == nil {
				t.Errorf("parseListen(%q): se esperaba error", c.in)
			}
			continue
		}
		if err != nil {
			t.Errorf("parseListen(%q): %v", c.in, err)
			continue
		}
		if spec.network != c.network || spec.addr != c.addr {
			t.Errorf("parseListen(%q) = %+v, se esperaba %s/%s", c.in, spec, c.network, c.addr)
		}
	}
}

// Con activación de systemd (y sin LISTEN) el destino por defecto es el
// socket: si no, el socket de la unidad quedaría huérfano.
func TestParseListenDefaultsToSocketUnderSystemdActivation(t *testing.T) {
	t.Setenv("LISTEN", "")
	t.Setenv("LISTEN_FDS", "1")
	// Nuestro pid: la activación "es para nosotros" (sólo se resuelve la
	// dirección aquí; no se sirve nada, el fd 3 no es un listener en tests).
	t.Setenv("LISTEN_PID", strconv.Itoa(os.Getpid()))

	spec, err := parseListen("")
	if err != nil {
		t.Fatalf("parseListen: %v", err)
	}
	if spec.network != "unix" || spec.addr != DefaultSocketPath {
		t.Fatalf("spec = %+v, want unix/%s", spec, DefaultSocketPath)
	}

	// Sin activación se conserva el comportamiento histórico (TCP).
	t.Setenv("LISTEN_FDS", "")
	spec, err = parseListen("")
	if err != nil {
		t.Fatalf("parseListen: %v", err)
	}
	if spec.network != "tcp" || spec.addr != ":8080" {
		t.Fatalf("spec = %+v, want tcp/:8080", spec)
	}
}

func TestParseRelay(t *testing.T) {
	r, err := parseRelay("3:9001")
	if err != nil || r == nil || r.cid != 3 || r.port != 9001 {
		t.Errorf("parseRelay = %+v, %v", r, err)
	}
	if r2, err := parseRelay(""); err != nil || r2 != nil {
		t.Errorf("vacío debe ser nil,nil: %v %v", r2, err)
	}
	for _, bad := range []string{"x:1", "3:", "1:2:3", "a:b"} {
		if _, err := parseRelay(bad); err == nil {
			t.Errorf("parseRelay(%q): se esperaba error", bad)
		}
	}
}

// fakeConn emula el parent: lee CONNECT…, responde y hace de eco.
func newFakeParent(t *testing.T, reply string, assertLine string) net.Conn {
	t.Helper()
	client, server := net.Pipe()
	t.Cleanup(func() { client.Close(); server.Close() })
	go func() {
		line, err := bufio.NewReader(server).ReadString('\n')
		if err != nil {
			return
		}
		if assertLine != "" && line != assertLine {
			t.Errorf("handshake = %q, se esperaba %q", line, assertLine)
		}
		if _, err := server.Write([]byte(reply)); err != nil {
			return
		}
		if reply == "OK\n" {
			// eco bidireccional
			buf := make([]byte, 64)
			for {
				n, err := server.Read(buf)
				if err != nil {
					return
				}
				if _, err := server.Write(buf[:n]); err != nil {
					return
				}
			}
		}
	}()
	return client
}

func TestRelayDialHandshakeOK(t *testing.T) {
	prev := vsockDial
	t.Cleanup(func() { vsockDial = prev })

	connRef := newFakeParent(t, "OK\n", "CONNECT prewww1.aeat.es:443\n")
	vsockDial = func(cid, port uint32) (net.Conn, error) {
		if cid != 3 || port != 9001 {
			t.Errorf("dial cid=%d port=%d", cid, port)
		}
		return connRef, nil
	}

	r := &relayTarget{cid: 3, port: 9001}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	conn, err := r.dialContext(ctx, "tcp", "prewww1.aeat.es:443")
	if err != nil {
		t.Fatalf("dialContext: %v", err)
	}
	defer conn.Close()

	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatalf("write: %v", err)
	}
	buf := make([]byte, 4)
	if _, err := conn.Read(buf); err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(buf) != "ping" {
		t.Errorf("eco = %q", buf)
	}
}

func TestRelayDialRejected(t *testing.T) {
	prev := vsockDial
	t.Cleanup(func() { vsockDial = prev })

	connRef := newFakeParent(t, "ERR\n", "")
	vsockDial = func(cid, port uint32) (net.Conn, error) { return connRef, nil }

	r := &relayTarget{cid: 3, port: 9001}
	_, err := r.dialContext(context.Background(), "tcp", "evil.example.com:443")
	if err == nil || !strings.Contains(err.Error(), "rechazado") {
		t.Fatalf("err = %v, se esperaba rechazo", err)
	}
}

// El socket huérfano de un arranque anterior se desvincula y el socket nace
// con 0660 (www-data habla, el resto no).
func TestServeUnixRemovesStaleSocketAndSetsPerms(t *testing.T) {
	t.Setenv("LISTEN_FDS", "") // sin activación por systemd
	t.Setenv("WPFE_SOCKET_MODE", "")

	sock := filepath.Join(t.TempDir(), "sub", "signer.sock")
	if err := os.MkdirAll(filepath.Dir(sock), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(sock, []byte("stale"), 0o600); err != nil {
		t.Fatalf("socket huérfano: %v", err)
	}

	ln, err := serveUnix(sock)
	if err != nil {
		t.Fatalf("serveUnix: %v", err)
	}
	defer ln.Close()

	info, err := os.Stat(sock)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if got := info.Mode().Perm(); got != 0o660 {
		t.Errorf("permisos del socket = %04o, want 0660", got)
	}

	// Conexión real: demuestra que el fichero huérfano fue reemplazado.
	conn, err := net.Dial("unix", sock)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	_ = conn.Close()
}

// WPFE_SOCKET_MODE manda (p. ej. 0660 root:www-data gestionado por systemd
// fuera de la activación) y un modo corrupto se rechaza en arranque.
func TestServeUnixHonoursExplicitMode(t *testing.T) {
	t.Setenv("LISTEN_FDS", "")
	t.Setenv("WPFE_SOCKET_MODE", "0662")

	sock := filepath.Join(t.TempDir(), "signer.sock")
	ln, err := serveUnix(sock)
	if err != nil {
		t.Fatalf("serveUnix: %v", err)
	}
	// El listener unix desvincula el socket al cerrarse: stat ANTES de Close.
	info, err := os.Stat(sock)
	_ = ln.Close()
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if got := info.Mode().Perm(); got != 0o662 {
		t.Errorf("permisos = %04o, want 0662", got)
	}

	t.Setenv("WPFE_SOCKET_MODE", "no-octal")
	if _, err := serveUnix(filepath.Join(t.TempDir(), "bad.sock")); err == nil {
		t.Fatal("un modo no octal debe rechazarse")
	}
}

// Con activación de systemd pero de OTRO proceso (LISTEN_PID ≠ getpid) el
// proceso no intenta robar el fd 3: cae en la ruta normal de creación.
func TestServeUnixIgnoresForeignSystemdActivation(t *testing.T) {
	t.Setenv("LISTEN_FDS", "1")
	t.Setenv("LISTEN_PID", "1") // no somos nosotros
	t.Setenv("WPFE_SOCKET_MODE", "")
	defer t.Setenv("LISTEN_FDS", "")

	sock := filepath.Join(t.TempDir(), "signer.sock")
	ln, err := serveUnix(sock)
	if err != nil {
		t.Fatalf("serveUnix: %v", err)
	}
	defer ln.Close()

	if _, err := os.Stat(sock); err != nil {
		t.Fatalf("el socket no se creó: %v", err)
	}
}

// Extremo a extremo: HTTP sobre el socket unix con el mux real.
func TestUnixSocketServesHTTP(t *testing.T) {
	t.Setenv("LISTEN_FDS", "")
	t.Setenv("WPFE_SOCKET_MODE", "")

	sock := filepath.Join(t.TempDir(), "signer.sock")
	ln, err := serveUnix(sock)
	if err != nil {
		t.Fatalf("serveUnix: %v", err)
	}

	srv := &http.Server{Handler: newMux()}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { srv.Close() })

	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, "unix", sock)
			},
		},
	}

	var resp *http.Response
	for attempt := 0; attempt < 50; attempt++ {
		resp, err = client.Get("http://localhost/health")
		if err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("GET /health por socket: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, body = %s", resp.StatusCode, body)
	}
}
