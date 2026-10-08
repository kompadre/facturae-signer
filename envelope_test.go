package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"facturae-signer/internal/hostid"
)

// withTransportConfig instala una clave de transporte temporal para los tests
// del envoltorio y la restaura al salir.
func withTransportConfig(t *testing.T) *signerConfig {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generar clave: %v", err)
	}
	old := activeConfig
	cfg := &signerConfig{privateKey: key, keyMode: "env"}
	activeConfig = cfg
	t.Cleanup(func() { activeConfig = old })
	return cfg
}

// El cuerpo WPFE1 llega y el handler ve el JSON original.
func TestEnvelopeOpensRequestBody(t *testing.T) {
	cfg := withTransportConfig(t)

	payload := []byte(`{"xml":"QUJD","certificate":"-----BEGIN"}`)
	blob, err := sealWPFE1(payload, &cfg.privateKey.PublicKey)
	if err != nil {
		t.Fatalf("sellar: %v", err)
	}

	var seen []byte
	h := envelopeMiddleware(func(w http.ResponseWriter, r *http.Request) {
		seen, _ = io.ReadAll(r.Body)
		writeJSON(w, http.StatusOK, map[string]string{"ok": "1"})
	})
	rec := httptest.NewRecorder()
	h(rec, httptest.NewRequest(http.MethodPost, "/sign", bytes.NewReader(blob)))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	if !bytes.Equal(seen, payload) {
		t.Fatalf("el handler vio %q, want %q", seen, payload)
	}
}

// Sin envoltorio pasa en claro (compatibilidad con staging), salvo que se exija.
func TestEnvelopeLegacyPlaintextPassesUnlessRequired(t *testing.T) {
	withTransportConfig(t)

	var seen []byte
	h := envelopeMiddleware(func(w http.ResponseWriter, r *http.Request) {
		seen, _ = io.ReadAll(r.Body)
		writeJSON(w, http.StatusOK, map[string]string{"ok": "1"})
	})

	plain := []byte(`{"xml":"QUJD"}`)
	rec := httptest.NewRecorder()
	h(rec, httptest.NewRequest(http.MethodPost, "/sign", bytes.NewReader(plain)))
	if rec.Code != http.StatusOK || !bytes.Equal(seen, plain) {
		t.Fatalf("legado: status=%d seen=%q", rec.Code, seen)
	}

	t.Setenv("WPFE_REQUIRE_ENVELOPE", "1")
	rec = httptest.NewRecorder()
	h(rec, httptest.NewRequest(http.MethodPost, "/sign", bytes.NewReader(plain)))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("con WPFE_REQUIRE_ENVELOPE el claro debe rechazarse: status = %d", rec.Code)
	}
}

// WPFE_SEAL_RESPONSES=1: la respuesta vuelve sellada con la misma clave AES
// que trajo el request, y el cliente la abre con decrypt (sin pareja propia).
func TestEnvelopeSealsResponsesWhenEnabled(t *testing.T) {
	cfg := withTransportConfig(t)
	t.Setenv("WPFE_SEAL_RESPONSES", "1")

	payload := []byte(`{"xml":"QUJD"}`)
	blob, err := sealWPFE1(payload, &cfg.privateKey.PublicKey)
	if err != nil {
		t.Fatalf("sellar request: %v", err)
	}

	responseBody := []byte(`{"signed_xml":"REFERU"}`)
	h := envelopeMiddleware(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write(responseBody)
	})
	rec := httptest.NewRecorder()
	h(rec, httptest.NewRequest(http.MethodPost, "/sign", bytes.NewReader(blob)))

	if rec.Code != http.StatusAccepted {
		t.Fatalf("status = %d", rec.Code)
	}
	if got := rec.Header().Get("Content-Type"); got != envelopeContentType {
		t.Fatalf("Content-Type = %q, want %q", got, envelopeContentType)
	}
	opened, err := decryptWPFE1(rec.Body.Bytes(), cfg.privateKey)
	if err != nil {
		t.Fatalf("abrir respuesta sellada: %v", err)
	}
	if !bytes.Equal(opened, responseBody) {
		t.Fatalf("respuesta = %q, want %q", opened, responseBody)
	}
}

// Sin clave de transporte cargada no se procesa nada (503, como los handlers).
func TestEnvelopeWithoutConfigRefuses(t *testing.T) {
	old := activeConfig
	activeConfig = nil
	t.Cleanup(func() { activeConfig = old })

	// Un blob cualquiera con prefijo WPFE1: no hay clave → 503.
	blob := append([]byte("WPFE1"), make([]byte, 64)...)
	h := envelopeMiddleware(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("el handler no debe ejecutarse sin clave")
	})
	rec := httptest.NewRecorder()
	h(rec, httptest.NewRequest(http.MethodPost, "/sign", bytes.NewReader(blob)))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rec.Code)
	}
}

// Documento de vínculo: campos presentes y receta de verificación del cliente
// reproducida aquí (mismo cálculo que hará PHP): payload recalculado desde los
// PEM y firma verificada contra host_public_key.
func TestTransportKeyJSONBindingDocument(t *testing.T) {
	t.Setenv("WPFE_KEY_MODE", "persistent")
	t.Setenv("WPFE_DATA_DIR", t.TempDir())
	t.Setenv("WPFE_MACHINE_ID", "maquina-de-pruebas")
	t.Setenv("WPFE_MASTER_SALT_FILE", "")

	cfg, err := loadSignerConfig()
	if err != nil {
		t.Fatalf("cargar config persistente: %v", err)
	}
	old := activeConfig
	activeConfig = cfg
	t.Cleanup(func() { activeConfig = old })

	rec := httptest.NewRecorder()
	transportKeyJSON(rec)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}

	var doc struct {
		TransportKey    string `json:"transport_key"`
		TransportKeyID  string `json:"transport_key_id"`
		HostCert        string `json:"host_cert"`
		HostPublicKey   string `json:"host_public_key"`
		HostFingerprint string `json:"host_fingerprint"`
		BindingAlg      string `json:"binding_alg"`
		Binding         string `json:"binding"`
		IssuedAt        string `json:"issued_at"`
		KeyMode         string `json:"key_mode"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &doc); err != nil {
		t.Fatalf("decodificar: %v", err)
	}
	if doc.KeyMode != "persistent" || doc.BindingAlg == "" || doc.Binding == "" {
		t.Fatalf("documento incompleto: %+v", doc)
	}
	if doc.HostFingerprint != cfg.host.Fingerprint {
		t.Fatalf("host_fingerprint = %q, want %q", doc.HostFingerprint, cfg.host.Fingerprint)
	}

	// SPKI DER a partir del PEM (exactamente lo que hará PHP: base64 del cuerpo).
	transportSPKI := pemBody(t, doc.TransportKey)
	hostSPKI := pemBody(t, doc.HostPublicKey)

	issuedAt, err := time.Parse(time.RFC3339, doc.IssuedAt)
	if err != nil {
		t.Fatalf("issued_at: %v", err)
	}
	payload := hostid.BindingPayload(transportSPKI, hostSPKI, issuedAt)

	sig, err := base64.StdEncoding.DecodeString(doc.Binding)
	if err != nil {
		t.Fatalf("binding b64: %v", err)
	}
	if err := hostid.VerifyBindingPEM([]byte(doc.HostPublicKey), payload, sig); err != nil {
		t.Fatalf("verificar vínculo con la receta del cliente: %v", err)
	}

	// Otra clave de transporte (es decir, un MitM re-sellando con su clave)
	// no verifica.
	forged := hostid.BindingPayload(pemBody(t, doc.HostCert), hostSPKI, issuedAt)
	if err := hostid.VerifyBindingPEM([]byte(doc.HostPublicKey), forged, sig); err == nil {
		t.Fatal("un payload con otra pública no debe verificar")
	}
}

// Sin identidad de host (modo env/generate de staging) no hay vínculo que
// servir: 501 y el cliente se queda con el PEM de siempre.
func TestTransportKeyJSONWithoutHostIdentity(t *testing.T) {
	withTransportConfig(t) // keyMode "env", sin host

	rec := httptest.NewRecorder()
	transportKeyJSON(rec)
	if rec.Code != http.StatusNotImplemented {
		t.Fatalf("status = %d, want 501", rec.Code)
	}
}

// pemBody devuelve el DER (SPKI) del cuerpo de un PEM PUBLIC KEY.
func pemBody(t *testing.T, pemStr string) []byte {
	t.Helper()
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		t.Fatalf("no es PEM: %.40q", pemStr)
	}
	return block.Bytes
}
