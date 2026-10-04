//go:build e2e

package main

// E2E por HTTP contra un signer levantado por `make e2e-local`
// (docker, WPFE_KEY_MODE=generate). Ejecución:
//
//	E2E_URL=http://127.0.0.1:18080 go test -tags e2e -count=1 .
//
// Sin E2E_URL el test se salta (el resto de la suite no lo ve: build tag).

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"
)

func TestHTTPEndToEndGenerateMode(t *testing.T) {
	base := os.Getenv("E2E_URL")
	if base == "" {
		t.Skip("E2E_URL no definido (lo define make e2e-local)")
	}
	client := &http.Client{Timeout: 15 * time.Second}

	// 1) health
	resp, err := client.Get(base + "/health")
	if err != nil {
		t.Fatalf("health: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || !strings.Contains(string(body), "ok") {
		t.Fatalf("health = %d %q", resp.StatusCode, body)
	}

	// 2) transport key (la que WordPress pegaría)
	resp, err = client.Get(base + "/v1/transport-key")
	if err != nil {
		t.Fatalf("transport-key: %v", err)
	}
	keyPEM, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || !strings.Contains(string(keyPEM), "BEGIN PUBLIC KEY") {
		t.Fatalf("transport-key = %d %.60q", resp.StatusCode, keyPEM)
	}
	block, _ := pem.Decode(keyPEM)
	if block == nil {
		t.Fatal("transport-key no es PEM")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		t.Fatalf("SPKI: %v", err)
	}
	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok {
		t.Fatal("la clave de transporte no es RSA")
	}

	// 3) attestation sin NSM -> 501 documentado
	resp, err = client.Get(base + "/v1/attestation")
	if err != nil {
		t.Fatalf("attestation: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotImplemented {
		t.Fatalf("attestation en docker = %d, se esperaba 501", resp.StatusCode)
	}

	// 4) bundle de prueba + WPFE1 cifrado a la pública servida -> /sign
	signKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	material := testBundlePEM(t, signKey)
	blob := encryptWPFE1(t, material, rsaPub)
	payload, _ := json.Marshal(map[string]string{
		"xml":         base64.StdEncoding.EncodeToString([]byte(sampleInvoice)),
		"certificate": base64.StdEncoding.EncodeToString(blob),
	})
	resp, err = client.Post(base+"/sign", "application/json", bytes.NewReader(payload))
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	signed, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("sign = %d %s", resp.StatusCode, signed)
	}
	if !strings.Contains(string(signed), "signed_xml") {
		t.Fatalf("respuesta sin signed_xml: %s", signed)
	}
	t.Log("e2e OK: generate-mode + endpoints + sign por HTTP")
}

// testBundlePEM: clave + cert autofirmado concatenados (formato bundle).
func testBundlePEM(t *testing.T, key *rsa.PrivateKey) []byte {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber:          bigOne(),
		Subject:               pkixName("E2E Bundle"),
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER := x509.MarshalPKCS1PrivateKey(key)
	var b bytes.Buffer
	_ = pem.Encode(&b, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: keyDER})
	_ = pem.Encode(&b, &pem.Block{Type: "CERTIFICATE", Bytes: der})
	return b.Bytes()
}

// (helpers mínimos para no arrastrar dependencias de los tests normales)
func bigOne() *big.Int { return big.NewInt(1) }

func pkixName(cn string) pkix.Name { return pkix.Name{CommonName: cn} }
