package main

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// testIdentity emula el escenario de producción: una clave de transporte K
// (clave privada del servicio) y el bundle PEM de firma que el plugin envía
// tras abrir el .p12 al subirlo (sin contraseña).
type testIdentity struct {
	cfg      *signerConfig
	material []byte
}

func newTestIdentity(t *testing.T) *testIdentity {
	t.Helper()

	transport, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("clave de transporte: %v", err)
	}
	signKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("clave de firma: %v", err)
	}
	material, err := mkKeyBundlePEM(t, signKey, mkSelfSignedCert(t, signKey))
	if err != nil {
		t.Fatalf("bundle: %v", err)
	}
	return &testIdentity{
		cfg:      &signerConfig{privateKey: transport},
		material: material,
	}
}

func (id *testIdentity) requestBody(t *testing.T, xml string, materialOverride []byte) string {
	t.Helper()
	material := materialOverride
	if material == nil {
		material = id.material
	}
	blob := encryptWPFE1(t, material, &id.cfg.privateKey.PublicKey)
	payload, err := json.Marshal(map[string]string{
		"xml":         base64.StdEncoding.EncodeToString([]byte(xml)),
		"certificate": base64.StdEncoding.EncodeToString(blob),
	})
	if err != nil {
		t.Fatalf("json: %v", err)
	}
	return string(payload)
}

func setActiveConfig(t *testing.T, cfg *signerConfig) {
	t.Helper()
	prev := activeConfig
	activeConfig = cfg
	t.Cleanup(func() { activeConfig = prev })
}

func postSign(t *testing.T, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/sign", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	newMux().ServeHTTP(rec, req)
	return rec
}

func TestSignHandlerHappyPath(t *testing.T) {
	id := newTestIdentity(t)
	setActiveConfig(t, id.cfg)

	rec := postSign(t, id.requestBody(t, sampleInvoice, nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", rec.Code, rec.Body.String())
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}

	var resp signResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("la respuesta no es JSON: %v", err)
	}
	if resp.SignedXML == "" {
		t.Fatal("signed_xml vacío")
	}
	signed, err := base64.StdEncoding.DecodeString(resp.SignedXML)
	if err != nil {
		t.Fatalf("signed_xml no es base64: %v", err)
	}
	if err := verifySignedXML(signed); err != nil {
		t.Fatalf("el XML firmado no verifica: %v", err)
	}
	if !strings.Contains(string(signed), "<ds:Signature") {
		t.Error("falta ds:Signature")
	}
	if !strings.Contains(string(signed), "<InvoiceNumber>2026-0001</InvoiceNumber>") {
		t.Error("el contenido de la factura desapareció")
	}
}

func TestSignHandlerUnconfigured(t *testing.T) {
	setActiveConfig(t, nil)

	id := newTestIdentity(t)
	rec := postSign(t, id.requestBody(t, sampleInvoice, nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want 503; body: %s", rec.Code, rec.Body.String())
	}
	var errResp errorResponse
	if json.Unmarshal(rec.Body.Bytes(), &errResp) != nil || !strings.Contains(errResp.Error, "WPFE_PRIVATE_KEY") {
		t.Errorf("cuerpo = %s", rec.Body.String())
	}
}

func TestSignHandlerRejectsBadWPFE1(t *testing.T) {
	id := newTestIdentity(t)
	setActiveConfig(t, id.cfg)

	body, _ := json.Marshal(map[string]string{
		"xml":         base64.StdEncoding.EncodeToString([]byte(sampleInvoice)),
		"certificate": base64.StdEncoding.EncodeToString([]byte("esto no es WPFE1")),
	})
	rec := postSign(t, string(body))
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400; body: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "WPFE1") {
		t.Errorf("mensaje de error inesperado: %s", rec.Body.String())
	}
}

func TestSignHandlerRejectsWrongTransportKey(t *testing.T) {
	id := newTestIdentity(t)
	setActiveConfig(t, id.cfg)

	other, _ := rsa.GenerateKey(rand.Reader, 2048)
	blob := encryptWPFE1(t, id.material, &other.PublicKey)
	body, _ := json.Marshal(map[string]string{
		"xml":         base64.StdEncoding.EncodeToString([]byte(sampleInvoice)),
		"certificate": base64.StdEncoding.EncodeToString(blob),
	})
	rec := postSign(t, string(body))
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400; body: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "clave privada") {
		t.Errorf("mensaje de error inesperado: %s", rec.Body.String())
	}
}

func TestSignHandlerRejectsLegacyPKCS12Blob(t *testing.T) {
	id := newTestIdentity(t)
	setActiveConfig(t, id.cfg)

	// Un PKCS#12 en bruto (subido con versiones antiguas del plugin, cuando
	// la contraseña vivía en el entorno del signer) ya no es aceptado.
	legacy := []byte{0x30, 0x82, 0x01, 0x07, 0x02, 0x01, 0x00, 0x30, 0x82, 0x01, 0x02}
	rec := postSign(t, id.requestBody(t, sampleInvoice, legacy))
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400; body: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "bundle PEM") {
		t.Errorf("mensaje de error inesperado: %s", rec.Body.String())
	}
}

func TestSignHandlerRejectsMalformedInnerXML(t *testing.T) {
	id := newTestIdentity(t)
	setActiveConfig(t, id.cfg)

	rec := postSign(t, id.requestBody(t, "<roto", nil))
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400; body: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "xml no válido") {
		t.Errorf("mensaje de error inesperado: %s", rec.Body.String())
	}
}

func TestSignHandlerBadRequests(t *testing.T) {
	id := newTestIdentity(t)
	setActiveConfig(t, id.cfg)

	cases := []struct {
		name string
		body string
	}{
		{"invalid json", "esto no es json"},
		{"missing xml", `{"certificate":"YQ=="}`},
		{"xml not base64", `{"xml":"!!!no-base64!!!","certificate":"YQ=="}`},
		{"missing certificate", `{"xml":"` + base64.StdEncoding.EncodeToString([]byte(sampleInvoice)) + `"}`},
		{"certificate not base64", `{"xml":"` + base64.StdEncoding.EncodeToString([]byte(sampleInvoice)) + `","certificate":"!!!"}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := postSign(t, tc.body)
			if rec.Code != http.StatusBadRequest {
				t.Errorf("status = %d, want 400; body: %s", rec.Code, rec.Body.String())
			}
			var errResp errorResponse
			if err := json.Unmarshal(rec.Body.Bytes(), &errResp); err != nil || errResp.Error == "" {
				t.Errorf("se esperaba cuerpo JSON de error, se obtuvo: %s", rec.Body.String())
			}
		})
	}
}

func TestHealth(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	rec := httptest.NewRecorder()
	newMux().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
	if strings.TrimSpace(rec.Body.String()) != "ok" {
		t.Errorf("body = %q, want ok", rec.Body.String())
	}
}

func TestUnknownRouteReturnsJSON404(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/nope", nil)
	rec := httptest.NewRecorder()
	newMux().ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", rec.Code)
	}
	var errResp errorResponse
	if json.Unmarshal(rec.Body.Bytes(), &errResp) != nil {
		t.Errorf("se esperaba cuerpo JSON, se obtuvo: %s", rec.Body.String())
	}
}

func TestSignWrongMethodReturns405(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/sign", nil)
	rec := httptest.NewRecorder()
	newMux().ServeHTTP(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want 405", rec.Code)
	}
}
