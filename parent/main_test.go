package main

import (
	"bufio"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

// dialFalso: en lugar de TCP real devuelve el extremo de un pipe y el test
// simula el destino.
func relayExchange(t *testing.T, allowed []string, target net.Conn, request string) (string, error) {
	t.Helper()
	client, server := net.Pipe()
	t.Cleanup(func() { client.Close(); server.Close() })

	done := make(chan error, 1)
	go func() {
		defer target.Close()
		done <- handleRelayAndReturn(server, allowed, target)
	}()

	_ = client.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := io.WriteString(client, request); err != nil {
		t.Fatalf("handshake write: %v", err)
	}
	reply, err := bufio.NewReader(client).ReadString('\n')
	if err != nil {
		return "", err
	}
	// Cerrar el cliente derrumba el pipe y permite que handleRelay termine.
	_ = client.Close()
	return reply, <-done
}

// handleRelayAndReturn envuelve handleRelay con un dial fijo (target).
func handleRelayAndReturn(server net.Conn, allowed []string, target net.Conn) error {
	handleRelay(server, allowed, func(network, addr string, timeout time.Duration) (net.Conn, error) {
		return target, nil
	})
	return nil
}

func TestRelayAllowsWhitelistedHost(t *testing.T) {
	// target = pipe cuyo otro extremo hace eco
	tgtClient, tgtServer := net.Pipe()
	t.Cleanup(func() { tgtClient.Close(); tgtServer.Close() })
	go func() {
		buf := make([]byte, 64)
		for {
			n, err := tgtServer.Read(buf)
			if err != nil {
				return
			}
			if _, err := tgtServer.Write(buf[:n]); err != nil {
				return
			}
		}
	}()

	reply, _ := relayExchange(t, []string{"prewww1.aeat.es:443"}, tgtClient,
		"CONNECT prewww1.aeat.es:443\n")
	if reply != "OK\n" {
		t.Fatalf("reply = %q, se esperaba OK", reply)
	}
}

func TestRelayDeniesNonWhitelistedHost(t *testing.T) {
	tgtClient, tgtServer := net.Pipe()
	t.Cleanup(func() { tgtClient.Close(); tgtServer.Close() })

	reply, _ := relayExchange(t, []string{"prewww1.aeat.es:443"}, tgtClient,
		"CONNECT evil.example.com:443\n")
	if reply != "ERR\n" {
		t.Fatalf("reply = %q, se esperaba ERR", reply)
	}
	_ = tgtServer
}

func TestRelayRejectsMalformedHandshake(t *testing.T) {
	tgtClient, tgtServer := net.Pipe()
	t.Cleanup(func() { tgtClient.Close(); tgtServer.Close() })

	reply, _ := relayExchange(t, []string{"any:1"}, tgtClient, "GET / HTTP/1.1\n")
	if !strings.HasPrefix(reply, "ERR") && reply == "" {
		// El servidor puede cerrar sin respuesta en protocolo inválido.
		return
	}
	if reply != "ERR\n" {
		t.Errorf("reply = %q", reply)
	}
	_ = tgtServer
}

func TestAllowedHost(t *testing.T) {
	allowed := splitAllowed(" Prewww1.aeat.es:443 , WWW1.Agenciatributaria.gob.es:443 ")
	if !allowedHost("prewww1.aeat.es:443", allowed) {
		t.Error("debe permitir host de la whitelist (case-insensitive)")
	}
	if allowedHost("prewww1.aeat.es:80", allowed) {
		t.Error("el puerto debe coincidir exactamente")
	}
	if allowedHost("evil.com:443", allowed) {
		t.Error("fuera de whitelist debe denegarse")
	}
}
