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
// (clave privada del servicio) y un PKCS#12 de firma con su contraseña.
type testIdentity struct {
	cfg *signerConfig
	p12 []byte
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
	p12, err := mkP12(t, signKey, "p12-pass")
	if err != nil {
		t.Fatalf("p12: %v", err)
	}
	return &testIdentity{
		cfg: &signerConfig{privateKey: transport, password: "p12-pass"},
		p12: p12,
	}
}

func (id *testIdentity) requestBody(t *testing.T, xml string, p12Override []byte) string {
	t.Helper()
	p12 := p12Override
	if p12 == nil {
		p12 = id.p12
	}
	blob := encryptWPFE1(t, p12, &id.cfg.privateKey.PublicKey)
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
	blob := encryptWPFE1(t, id.p12, &other.PublicKey)
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

func TestSignHandlerRejectsWrongP12Password(t *testing.T) {
	id := newTestIdentity(t)
	id.cfg.password = "contraseña-equivocada"
	setActiveConfig(t, id.cfg)

	rec := postSign(t, id.requestBody(t, sampleInvoice, nil))
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400; body: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "PKCS#12") {
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
