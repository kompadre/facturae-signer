package main

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/mdlayher/vsock"
)

// DefaultSocketPath es el socket local por defecto (modo VPS/mismo host).
// Se mueve con WPFE_SOCKET o con LISTEN directamente.
const DefaultSocketPath = "/run/facturae-signer/signer.sock"

// LISTEN define dónde sirve el signer:
//
//	":8080" / "tcp:addr"    → TCP (docker/staging, por defecto)
//	"vsock:9000"            → vsock (enclave; el parent hace de puente)
//	"unix:/run/…/sock.sock" → Unix Domain Socket: el plugin habla por él
//	                           en el mismo host (www-data entra con 0660)
type listenSpec struct {
	network string // "tcp" | "vsock" | "unix"
	addr    string // tcp: dirección; vsock: puerto; unix: ruta del socket
}

func parseListen(s string) (listenSpec, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		// Con activación por systemd y sin LISTEN explícito, el destino es
		// el socket: si no, el proceso serviría en TCP y el socket que creó
		// systemd quedaría huérfano (conexiones rechazadas, sin error claro).
		if systemdActivationActive() {
			return listenSpec{network: "unix", addr: DefaultSocketPath}, nil
		}
		return listenSpec{network: "tcp", addr: ":8080"}, nil
	}
	if strings.HasPrefix(s, "tcp:") {
		addr := strings.TrimPrefix(s, "tcp:")
		if addr == "" {
			return listenSpec{}, fmt.Errorf("LISTEN tcp sin dirección")
		}
		return listenSpec{network: "tcp", addr: addr}, nil
	}
	if strings.HasPrefix(s, "unix:") {
		path := strings.TrimPrefix(s, "unix:")
		if path == "" {
			return listenSpec{}, fmt.Errorf("LISTEN unix: falta la ruta del socket")
		}
		return listenSpec{network: "unix", addr: path}, nil
	}
	if strings.HasPrefix(s, "vsock:") {
		port := strings.TrimPrefix(s, "vsock:")
		if _, err := strconv.ParseUint(port, 10, 32); err != nil {
			return listenSpec{}, fmt.Errorf("LISTEN vsock: puerto no válido (%q)", port)
		}
		return listenSpec{network: "vsock", addr: port}, nil
	}
	return listenSpec{network: "tcp", addr: s}, nil
}

func serveListener(spec listenSpec) (net.Listener, error) {
	switch spec.network {
	case "vsock":
		port, _ := strconv.ParseUint(spec.addr, 10, 32)
		return vsock.Listen(uint32(port), nil)
	case "unix":
		return serveUnix(spec.addr)
	}
	return net.Listen(spec.network, spec.addr)
}

// serveUnix monta el socket local, con dos caminos y ambos respetando los
// permisos:
//
//   - Activación por systemd (LISTEN_FDS): el socket lo ha creado systemd ya
//     con SocketMode=0660 / SocketUser / SocketGroup; el proceso no lo toca
//     ni lo desvincula (borrarlo rompería la activación).
//   - Propio: se desvincula un socket huérfano de un arranque anterior —sólo
//     en esta rama— y se escucha fijando el modo con WPFE_SOCKET_MODE
//     (0660 por defecto: www-data habla, el resto no) y, si se indican,
//     WPFE_SOCKET_UID/WPFE_SOCKET_GID (p. ej. root:www-data).
func serveUnix(path string) (net.Listener, error) {
	if activated, err := systemdActivatedListener(); err != nil {
		return nil, err
	} else if activated != nil {
		return activated, nil
	}

	// Socket huérfano de un proceso que murió: sin esto net.Listen falla
	// con "address already in use".
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return nil, fmt.Errorf("unix: limpiar socket %s: %w", path, err)
	}
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o750); err != nil {
			return nil, fmt.Errorf("unix: crear %s: %w", dir, err)
		}
	}

	ln, err := net.Listen("unix", path)
	if err != nil {
		return nil, fmt.Errorf("unix: escuchar en %s: %w", path, err)
	}

	mode := strings.TrimSpace(os.Getenv("WPFE_SOCKET_MODE"))
	if mode == "" {
		mode = "0660"
	}
	parsed, err := strconv.ParseUint(strings.TrimPrefix(mode, "0"), 8, 32)
	if err != nil {
		_ = ln.Close()
		return nil, fmt.Errorf("unix: WPFE_SOCKET_MODE no es octal (%q)", mode)
	}
	if err := os.Chmod(path, os.FileMode(parsed)); err != nil {
		_ = ln.Close()
		return nil, fmt.Errorf("unix: chmod %s: %w", path, err)
	}

	uid, hasUID := socketID("WPFE_SOCKET_UID")
	gid, hasGID := socketID("WPFE_SOCKET_GID")
	if (hasUID || hasGID) && os.Geteuid() == 0 {
		// Se conserva el valor no indicado (chown exige ambos).
		if st, err := os.Stat(path); err == nil {
			stat, ok := st.Sys().(*syscall.Stat_t)
			if ok {
				if !hasUID {
					uid = int(stat.Uid)
				}
				if !hasGID {
					gid = int(stat.Gid)
				}
			}
		}
		if err := os.Chown(path, uid, gid); err != nil {
			_ = ln.Close()
			return nil, fmt.Errorf("unix: chown %s: %w", path, err)
		}
	}

	return ln, nil
}

// socketID lee un uid/gid numérico del entorno (falso si no es válido).
func socketID(name string) (int, bool) {
	raw := strings.TrimSpace(os.Getenv(name))
	if raw == "" {
		return 0, false
	}
	id, err := strconv.Atoi(raw)
	if err != nil || id < 0 {
		return 0, false
	}
	return id, true
}

// systemdActivationActive reports si systemd nos ha pasado ya el socket.
func systemdActivationActive() bool {
	if strings.TrimSpace(os.Getenv("LISTEN_FDS")) == "" {
		return false
	}
	fds, err := strconv.Atoi(os.Getenv("LISTEN_FDS"))
	if err != nil || fds < 1 {
		return false
	}
	pid, err := strconv.Atoi(os.Getenv("LISTEN_PID"))
	return err == nil && pid == os.Getpid()
}

// systemdActivatedListener devuelve el listener que entregó systemd
// (LISTEN_FDS + LISTEN_PID) o nil si no hay activación. En ese caso el
// socket ya lleva los permisos declarados en la unidad y NO debe tocarse.
func systemdActivatedListener() (net.Listener, error) {
	if !systemdActivationActive() {
		return nil, nil
	}
	file := os.NewFile(uintptr(3), "systemd-socket") // SD_LISTEN_FDS_START = 3
	ln, err := net.FileListener(file)
	if err != nil {
		return nil, fmt.Errorf("unix: listener de systemd: %w", err)
	}
	return ln, nil
}

// relayTarget: VSOCK_OUTBOUND="cid:puerto" — el enclave sale a Internet a
// través del parent: conecta por vsock y negocia con CONNECT.
//
//	→ "CONNECT <host>:<port>\n"
//	← "OK\n" (relay abierto) | "ERR\n" (rechazado por whitelist)
type relayTarget struct {
	cid  uint32
	port uint32
}

// outboundRelay activo (nil = conexión directa, modo docker/staging).
var outboundRelay *relayTarget

// vsockDial es sustituible en tests (no hay vsock en todos los entornos).
var vsockDial = func(cid, port uint32) (net.Conn, error) {
	return vsock.Dial(cid, port, nil)
}

func parseRelay(s string) (*relayTarget, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, nil
	}
	parts := strings.Split(s, ":")
	if len(parts) != 2 {
		return nil, fmt.Errorf("VSOCK_OUTBOUND inválido (%q): se espera cid:puerto", s)
	}
	cid, err := strconv.ParseUint(parts[0], 10, 32)
	if err != nil {
		return nil, fmt.Errorf("VSOCK_OUTBOUND cid no válido (%q)", parts[0])
	}
	port, err := strconv.ParseUint(parts[1], 10, 32)
	if err != nil {
		return nil, fmt.Errorf("VSOCK_OUTBOUND puerto no válido (%q)", parts[1])
	}
	return &relayTarget{cid: uint32(cid), port: uint32(port)}, nil
}

// dialContext conecta con el destino final a través del parent (vsock +
// CONNECT). La resolución y la whitelist viven en el parent: el enclave no
// tiene red propia.
func (r *relayTarget) dialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	conn, err := vsockDial(r.cid, r.port)
	if err != nil {
		return nil, fmt.Errorf("relay vsock: %w", err)
	}
	if err := conn.SetDeadline(deadlineFromContext(ctx)); err != nil {
		conn.Close()
		return nil, err
	}
	if _, err := io.WriteString(conn, "CONNECT "+addr+"\n"); err != nil {
		conn.Close()
		return nil, fmt.Errorf("relay: negociar con el parent: %w", err)
	}
	reply := make([]byte, 3)
	if _, err := io.ReadFull(conn, reply); err != nil {
		conn.Close()
		return nil, fmt.Errorf("relay: respuesta del parent: %w", err)
	}
	if string(reply) != "OK\n" {
		conn.Close()
		return nil, fmt.Errorf("relay rechazado por el parent (%s)", strings.TrimSpace(string(reply)))
	}
	// Post-handshake: sin límite (la conexión es del Transport TLS).
	_ = conn.SetDeadline(time.Time{})
	return conn, nil
}

func deadlineFromContext(ctx context.Context) time.Time {
	if dl, ok := ctx.Deadline(); ok {
		return dl
	}
	return time.Now().Add(30 * time.Second)
}
