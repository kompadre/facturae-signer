// parent es el proceso del HOST que puentea WordPress ↔ enclave (Nitro):
//
//   - Inbound: TCP (INBOUND_LISTEN, :8080) → vsock(ENCLAVE_CID,
//     ENCLAVE_VSOCK_PORT). Es la URL que el plugin usa como signing_url.
//   - Relay de salida: el enclave conecta por vsock (RELAY_VSOCK_PORT) y
//     negocia "CONNECT host:port\n" → "OK\n"|"ERR\n". El parent sólo
//     marca la conexión si host:port está en la whitelist (la AEAT); la
//     relay es de bytes crudos, así el mTLS con la AEAT sigue de extremo
//     a extremo en el enclave.
//
// El parent NO guarda secretos: ni claves, ni certificados, ni blobs.
package main

import (
	"bufio"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strings"
	"time"

	"github.com/mdlayher/vsock"
)

const defaultAllowedHosts = "prewww1.aeat.es:443,www1.agenciatributaria.gob.es:443," +
	"prewww10.aeat.es:443,www10.agenciatributaria.gob.es:443"

func envOr(key, def string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return def
}

func main() {
	inbound := envOr("INBOUND_LISTEN", ":8080")
	encPort := envOr("ENCLAVE_VSOCK_PORT", "9000")
	relayPort := envOr("RELAY_VSOCK_PORT", "9001")
	allowed := splitAllowed(envOr("ALLOWED_HOSTS", defaultAllowedHosts))

	cidStr := strings.TrimSpace(os.Getenv("ENCLAVE_CID"))
	if cidStr == "" {
		log.Fatal("falta ENCLAVE_CID (id de describe-enclaves tras nitro-cli run-enclave)")
	}
	var cid uint32
	if _, err := fmt.Sscanf(cidStr, "%d", &cid); err != nil {
		log.Fatalf("ENCLAVE_CID no válido (%q): %v", cidStr, err)
	}
	var encPortNum uint32
	if _, err := fmt.Sscanf(encPort, "%d", &encPortNum); err != nil {
		log.Fatalf("ENCLAVE_VSOCK_PORT no válido (%q)", encPort)
	}

	// Relay de salida (el enclave habla con nosotros por vsock).
	if relayPort != "0" && relayPort != "" {
		var rp uint32
		if _, err := fmt.Sscanf(relayPort, "%d", &rp); err != nil {
			log.Fatalf("RELAY_VSOCK_PORT no válido (%q)", relayPort)
		}
		ln, err := vsock.Listen(rp, nil)
		if err != nil {
			log.Fatalf("relay vsock %d: %v", rp, err)
		}
		log.Printf("relay de salida escuchando en vsock:%d (whitelist: %s)", rp, strings.Join(allowed, ", "))
		go acceptLoop(ln, func(c net.Conn) { go handleRelay(c, allowed, net.DialTimeout) })
	}

	// Inbound desde WP: TCP → vsock del enclave.
	ln, err := net.Listen("tcp", inbound)
	if err != nil {
		log.Fatalf("listen %s: %v", inbound, err)
	}
	log.Printf("inbound escuchando en %s → vsock cid=%d puerto=%s", inbound, cid, encPort)
	go acceptLoop(ln, func(c net.Conn) {
		enc, err := vsock.Dial(cid, encPortNum, nil)
		if err != nil {
			log.Printf("dial al enclave: %v", err)
			c.Close()
			return
		}
		pipe(c, enc)
	})

	// (acceptLoop de inbound bloquea en main vía canal abajo)
	select {}
}

func splitAllowed(s string) []string {
	var out []string
	for _, h := range strings.Split(s, ",") {
		if h = strings.ToLower(strings.TrimSpace(h)); h != "" {
			out = append(out, h)
		}
	}
	return out
}

type dialFn func(network, addr string, timeout time.Duration) (net.Conn, error)

func acceptLoop(ln net.Listener, handle func(net.Conn)) {
	for {
		c, err := ln.Accept()
		if err != nil {
			log.Printf("accept: %v", err)
			return
		}
		handle(c)
	}
}

// handleRelay implementa el protocolo CONNECT del enclave.
func handleRelay(conn net.Conn, allowed []string, dial dialFn) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(15 * time.Second))

	line, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		log.Printf("relay: handshake ilegible: %v", err)
		return
	}
	addr := strings.TrimSpace(strings.TrimPrefix(line, "CONNECT "))
	if addr == "" || !strings.HasPrefix(line, "CONNECT ") {
		_, _ = io.WriteString(conn, "ERR\n")
		log.Printf("relay: protocolo inválido (%q)", strings.TrimSpace(line))
		return
	}

	if !allowedHost(addr, allowed) {
		_, _ = io.WriteString(conn, "ERR\n")
		log.Printf("relay: DENEGADO %s (fuera de whitelist)", addr)
		return
	}

	target, err := dial("tcp", addr, 10*time.Second)
	if err != nil {
		_, _ = io.WriteString(conn, "ERR\n")
		log.Printf("relay: dial %s: %v", addr, err)
		return
	}
	defer target.Close()

	if _, err := io.WriteString(conn, "OK\n"); err != nil {
		return
	}
	_ = conn.SetDeadline(time.Time{})
	log.Printf("relay: permitido %s", addr)
	pipe(conn, target)
}

func allowedHost(addr string, allowed []string) bool {
	addr = strings.ToLower(addr)
	for _, a := range allowed {
		if addr == a {
			return true
		}
	}
	return false
}

// pipe copia en ambos sentidos; al primer cierre derrumba las dos copias
// (si no, la copia que esperaba datos se quedaría colgada).
func pipe(a, b net.Conn) {
	done := make(chan struct{}, 2)
	cp := func(dst, src net.Conn) {
		_, _ = io.Copy(dst, src)
		done <- struct{}{}
	}
	go cp(a, b)
	go cp(b, a)
	<-done
	_ = a.Close()
	_ = b.Close()
	<-done
}
