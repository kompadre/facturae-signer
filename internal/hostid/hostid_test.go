package hostid

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func paths(t *testing.T) (string, string) {
	t.Helper()
	dir := t.TempDir()
	return filepath.Join(dir, "host.cert"), filepath.Join(dir, "host.key")
}

func writeTestPEM(t *testing.T, path, blockType string, der []byte, mode os.FileMode) {
	t.Helper()
	data := pem.EncodeToMemory(&pem.Block{Type: blockType, Bytes: der})
	if err := os.WriteFile(path, data, mode); err != nil {
		t.Fatalf("escribir %s: %v", path, err)
	}
}

func TestLoadOrCreateGeneratesStableIdentity(t *testing.T) {
	certPath, keyPath := paths(t)

	id1, err := LoadOrCreate(certPath, keyPath, "vps-pruebas")
	if err != nil {
		t.Fatalf("alta: %v", err)
	}
	if !strings.HasPrefix(id1.Fingerprint, "sha256:") {
		t.Fatalf("huella = %q, want prefijo sha256:", id1.Fingerprint)
	}

	// Segunda carga: la identidad (y por tanto la huella) es estable; eso es
	// exactamente lo que WordPress fija en Ajustes.
	id2, err := LoadOrCreate(certPath, keyPath, "vps-pruebas")
	if err != nil {
		t.Fatalf("segunda carga: %v", err)
	}
	if id1.Fingerprint != id2.Fingerprint {
		t.Fatalf("la huella cambió: %s → %s", id1.Fingerprint, id2.Fingerprint)
	}
	if !bytes.Equal(id1.SPKI, id2.SPKI) {
		t.Fatal("la SPKI cambió entre cargas")
	}

	info, err := os.Stat(keyPath)
	if err != nil {
		t.Fatalf("stat clave: %v", err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Errorf("permisos de host.key = %04o, want 0600", got)
	}
}

// Si falta una mitad no se regenera: eso cambiaría la huella que el cliente
// ya tiene fijada y rompería la confianza sin que el operador lo decidiera.
func TestHalfIdentityIsNeverRegenerated(t *testing.T) {
	certPath, keyPath := paths(t)
	if err := os.WriteFile(certPath, []byte("-----BEGIN CERTIFICATE-----\nzzz\n-----END CERTIFICATE-----\n"), 0o644); err != nil {
		t.Fatalf("preparar: %v", err)
	}

	if _, err := LoadOrCreate(certPath, keyPath, "h"); !errors.Is(err, ErrHalfIdentity) {
		t.Fatalf("err = %v, want ErrHalfIdentity", err)
	}
	if _, err := os.Stat(keyPath); err == nil {
		t.Fatal("no debe generarse una clave nueva cuando sólo existe el cert")
	}
}

func TestBindingSignAndVerify(t *testing.T) {
	certPath, keyPath := paths(t)
	id, err := LoadOrCreate(certPath, keyPath, "vps-pruebas")
	if err != nil {
		t.Fatalf("alta: %v", err)
	}
	transportSPKI := []byte("spki-de-la-clave-de-transporte")
	at := time.Date(2026, 10, 8, 12, 0, 0, 0, time.UTC)

	alg, sig, payload, err := id.SignBinding(transportSPKI, at)
	if err != nil {
		t.Fatalf("firmar: %v", err)
	}
	if alg != AlgECDSAP256 {
		t.Fatalf("alg = %q, want %q", alg, AlgECDSAP256)
	}

	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatalf("leer cert: %v", err)
	}
	if err := VerifyBindingPEM(certPEM, payload, sig); err != nil {
		t.Fatalf("verificar: %v", err)
	}

	// Payload distinto (otra clave de transporte) no verifica.
	otherPayload := BindingPayload([]byte("spki-ajeno"), id.SPKI, at)
	if err := VerifyBindingPEM(certPEM, otherPayload, sig); !errors.Is(err, ErrVerify) {
		t.Fatalf("payload ajeno: err = %v, want ErrVerify", err)
	}

	// Firma manipulada tampoco.
	broken := append([]byte(nil), sig...)
	broken[0] ^= 0xff
	if err := VerifyBindingPEM(certPEM, payload, broken); !errors.Is(err, ErrVerify) {
		t.Fatalf("firma manipulada: err = %v, want ErrVerify", err)
	}

	// Certificado ajeno tampoco: éso es lo que un MitM de /etc/hosts no puede
	// falsear sin poseer la clave privada del host real.
	otherCert, otherKey := paths(t)
	if _, err := LoadOrCreate(otherCert, otherKey, "atacante"); err != nil {
		t.Fatalf("alta ajena: %v", err)
	}
	otherCertPEM, err := os.ReadFile(otherCert)
	if err != nil {
		t.Fatalf("leer cert ajeno: %v", err)
	}
	if err := VerifyBindingPEM(otherCertPEM, payload, sig); !errors.Is(err, ErrVerify) {
		t.Fatalf("cert ajeno: err = %v, want ErrVerify", err)
	}
}

// Identidad RSA: el caso Let's Encrypt, cuando el operador apunta
// WPFE_HOST_* al par TLS del sitio y el vínculo se firma con esa clave.
func TestRSAIdentityBinding(t *testing.T) {
	dir := t.TempDir()
	rsaPriv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generar RSA: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "site.example"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().AddDate(1, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &rsaPriv.PublicKey, rsaPriv)
	if err != nil {
		t.Fatalf("autofirmar: %v", err)
	}

	certPath := filepath.Join(dir, "site.crt")
	keyPath := filepath.Join(dir, "site.key")
	writeTestPEM(t, certPath, "CERTIFICATE", der, 0o644)
	keyDER, err := x509.MarshalPKCS8PrivateKey(rsaPriv)
	if err != nil {
		t.Fatalf("serializar clave: %v", err)
	}
	writeTestPEM(t, keyPath, "PRIVATE KEY", keyDER, 0o600)

	id, err := Load(certPath, keyPath)
	if err != nil {
		t.Fatalf("cargar par TLS: %v", err)
	}

	alg, sig, payload, err := id.SignBinding([]byte("spki-transporte"), time.Now())
	if err != nil {
		t.Fatalf("firmar: %v", err)
	}
	if alg != AlgRSAPKCS1 {
		t.Fatalf("alg = %q, want %q", alg, AlgRSAPKCS1)
	}
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatalf("leer cert: %v", err)
	}
	if err := VerifyBindingPEM(certPEM, payload, sig); err != nil {
		t.Fatalf("verificar RSA: %v", err)
	}
}

func TestLoadRejectsNonPEMCertificate(t *testing.T) {
	certPath, keyPath := paths(t)
	if err := os.WriteFile(certPath, []byte("basura"), 0o644); err != nil {
		t.Fatalf("preparar: %v", err)
	}
	if err := os.WriteFile(keyPath, []byte("basura"), 0o600); err != nil {
		t.Fatalf("preparar: %v", err)
	}
	if _, err := Load(certPath, keyPath); err == nil {
		t.Fatal("un certificado que no es PEM debe fallar")
	}
}
