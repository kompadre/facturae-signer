package main

import (
	"context"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/mdlayher/vsock"
)

// LISTEN define dónde sirve el signer:
//
//	":8080" / "tcp:addr"  → TCP (docker/staging, por defecto)
//	"vsock:9000"          → vsock (enclave; el parent hace de puente)
type listenSpec struct {
	network string // "tcp" | "vsock"
	addr    string // tcp: dirección; vsock: puerto
}

func parseListen(s string) (listenSpec, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return listenSpec{network: "tcp", addr: ":8080"}, nil
	}
	if strings.HasPrefix(s, "tcp:") {
		addr := strings.TrimPrefix(s, "tcp:")
		if addr == "" {
			return listenSpec{}, fmt.Errorf("LISTEN tcp sin dirección")
		}
		return listenSpec{network: "tcp", addr: addr}, nil
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
	if spec.network == "vsock" {
		port, _ := strconv.ParseUint(spec.addr, 10, 32)
		return vsock.Listen(uint32(port), nil)
	}
	return net.Listen(spec.network, spec.addr)
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
