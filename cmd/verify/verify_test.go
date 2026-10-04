package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
)

// buildDebugDoc crea un documento sintético con forma de attestation doc del
// NSM (mismas claves de mapa) firmado con ECDSA — suficiente para ejercitar
// toda la lógica de verify sin hardware Nitro.
func buildTestDoc(t *testing.T, pcr0, pcr2 []byte, transportPub []byte, nonce []byte, signKey *ecdsa.PrivateKey, signCertDER []byte) []byte {
	t.Helper()

	doc := map[string]any{
		"version":             uint64(2),
		"timestamp":           uint64(time.Now().UnixMilli()),
		"digest_algorithm":    "SHA384",
		"pcr0":                pcr0,
		"pcr2":                pcr2,
		"certificate":         signCertDER,
		"public_key":          transportPub,
		"user_data":           []byte("facturae-signer/test"),
		"signature_algorithm": "SHA256withECDSA",
	}
	if nonce != nil {
		doc["nonce"] = nonce
	}

	// Firma con la codificación Core Deterministic (la misma que verify prueba).
	unsigned := map[string]any{}
	for k, v := range doc {
		unsigned[k] = v
	}
	em, err := cbor.CoreDetEncOptions().EncMode()
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if err := em.NewEncoder(&buf).Encode(unsigned); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(buf.Bytes())
	sig, err := ecdsa.SignASN1(rand.Reader, signKey, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	doc["signature"] = sig

	out, err := cbor.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func newSigningIdentity(t *testing.T) (*ecdsa.PrivateKey, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "NSM Attestation Key (test)"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return key, der
}

func writeTemp(t *testing.T, name, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func writeMeasurements(t *testing.T, m map[string]string) string {
	t.Helper()
	b, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return writeTemp(t, "measurements.json", string(b))
}

func spkiPEMFile(t *testing.T) (string, []byte) {
	t.Helper()
	rk, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&rk.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	pemStr := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
	return writeTemp(t, "key.pem", pemStr), der
}

func TestVerifyNitroDocument(t *testing.T) {
	signKey, signCertDER := newSigningIdentity(t)
	keyFile, transportPub := spkiPEMFile(t)
	pcr0 := make([]byte, 32)
	pcr2 := make([]byte, 32)
	for i := range pcr0 {
		pcr0[i] = byte(i + 1)
		pcr2[i] = byte(0xA0 + i)
	}
	nonce := []byte("nonce-de-prueba")
	doc := buildTestDoc(t, pcr0, pcr2, transportPub, nonce, signKey, signCertDER)
	docFile := writeTemp(t, "doc.cbor", string(doc))
	meas := writeMeasurements(t, map[string]string{
		"mode": "nitro",
		"pcr0": hex.EncodeToString(pcr0),
		"pcr2": hex.EncodeToString(pcr2),
	})

	// Root = el propio cert autofirmado (CheckSignatureFrom funciona con issuer==subject)
	rootFile := writeTemp(t, "root.pem", string(pem.EncodeToMemory(&pem.Block{
		Type: "CERTIFICATE", Bytes: signCertDER,
	})))

	if err := run(options{
		doc: docFile, measurements: meas, key: keyFile, nonce: "b64:" + base64.StdEncoding.EncodeToString(nonce), root: rootFile,
	}); err != nil {
		t.Fatalf("verify completo: %v", err)
	}

	// PCR incorrecto -> fallo.
	badMeas := writeMeasurements(t, map[string]string{
		"mode": "nitro", "pcr0": hex.EncodeToString(make([]byte, 32)), "pcr2": hex.EncodeToString(pcr2),
	})
	if err := run(options{doc: docFile, measurements: badMeas}); err == nil {
		t.Fatal("pcr0 distinto debe fallar")
	}

	// Clave pública distinta -> fallo.
	otherFile, _ := spkiPEMFile(t)
	if err := run(options{doc: docFile, measurements: meas, key: otherFile}); err == nil {
		t.Fatal("public_key distinta debe fallar")
	}

	// Nonce distinto -> fallo (replay).
	if err := run(options{doc: docFile, measurements: meas, nonce: "otro-nonce"}); err == nil {
		t.Fatal("nonce distinto debe fallar")
	}
}

func TestVerifySimulatedBinary(t *testing.T) {
	bin := []byte("#!/bin/sh\necho signer-fake\n")
	binFile := writeTemp(t, "signer", string(bin))
	if err := os.Chmod(binFile, 0o755); err != nil {
		t.Fatal(err)
	}
	sum32 := sha256.Sum256(bin)

	// Doc simulado mínimo (no se usa pcr*).
	signKey, signCertDER := newSigningIdentity(t)
	_, transportPub := spkiPEMFile(t)
	doc := buildTestDoc(t, nil, nil, transportPub, nil, signKey, signCertDER)
	docFile := writeTemp(t, "doc.cbor", string(doc))

	meas := writeMeasurements(t, map[string]string{
		"mode":          "simulated",
		"binary_sha256": hex.EncodeToString(sum32[:]),
		"note":          "SIMULACIÓN local",
	})
	if err := run(options{doc: docFile, measurements: meas, binary: binFile}); err != nil {
		t.Fatalf("simulated: %v", err)
	}

	// Otro binario -> fallo.
	other := writeMeasurements(t, map[string]string{
		"mode": "simulated", "binary_sha256": hex.EncodeToString(make([]byte, 32)),
	})
	if err := run(options{doc: docFile, measurements: other, binary: binFile}); err == nil {
		t.Fatal("binary distinto debe fallar")
	}
}

func TestVerifyDebugZeroPCRs(t *testing.T) {
	signKey, signCertDER := newSigningIdentity(t)
	_, transportPub := spkiPEMFile(t)
	zeros := make([]byte, 32)
	doc := buildTestDoc(t, zeros, zeros, transportPub, nil, signKey, signCertDER)
	docFile := writeTemp(t, "doc.cbor", string(doc))

	meas := writeMeasurements(t, map[string]string{
		"mode": "nitro-debug",
	})
	// Sólo comprobación de PCRs (sin -key/-root): el modo debug acepta ceros.
	if err := run(options{doc: docFile, measurements: meas}); err != nil {
		t.Fatalf("nitro-debug con ceros: %v", err)
	}

}

func TestVerifyRejectsNonCBOR(t *testing.T) {
	docFile := writeTemp(t, "doc.txt", "esto no es cbor")
	meas := writeMeasurements(t, map[string]string{"mode": "nitro", "pcr0": "00", "pcr2": "00"})
	if err := run(options{doc: docFile, measurements: meas}); err == nil {
		t.Fatal("CBOR inválido debe fallar")
	}
}
