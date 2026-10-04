package main

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/fxamacker/cbor/v2"
)

// --- NSM (protocolo /dev/nsm sobre un pipe falso) ---

type stubAttestation struct {
	pk, ud, nonce []byte
	doc           []byte
	err           error
}

func (s *stubAttestation) GetAttestationDoc(publicKey, userData, nonce []byte) ([]byte, error) {
	s.pk = append([]byte(nil), publicKey...)
	s.ud = append([]byte(nil), userData...)
	s.nonce = append([]byte(nil), nonce...)
	return s.doc, s.err
}

func TestNsmDeviceProtocolRoundtrip(t *testing.T) {
	client, server := net.Pipe()
	t.Cleanup(func() { client.Close(); server.Close() })

	go func() {
		defer server.Close()
		payload, err := readFrame(server)
		if err != nil {
			return
		}
		var req nsmRequest
		if err := cbor.Unmarshal(payload, &req); err != nil {
			t.Errorf("petición CBOR inválida: %v", err)
			return
		}
		if req.Version != 1 || req.Request.Type != "GetAttestationDoc" {
			t.Errorf("petición = %+v", req)
		}
		if string(req.Request.PublicKey) != "PK-DER" {
			t.Errorf("public_key = %q", req.Request.PublicKey)
		}
		resp, _ := cbor.Marshal(nsmResponse{
			Version: 1,
			Response: nsmResponsePayload{
				Error:          0,
				AttestationDoc: []byte("FAKE-DOC"),
			},
		})
		_ = writeFrame(server, resp)
	}()

	d := &nsmDevice{conn: client}
	doc, err := d.GetAttestationDoc([]byte("PK-DER"), []byte("ud"), []byte("n"))
	if err != nil {
		t.Fatalf("GetAttestationDoc: %v", err)
	}
	if string(doc) != "FAKE-DOC" {
		t.Errorf("doc = %q", doc)
	}
}

func TestNsmDeviceErrorCode(t *testing.T) {
	client, server := net.Pipe()
	t.Cleanup(func() { client.Close(); server.Close() })

	go func() {
		defer server.Close()
		if _, err := readFrame(server); err != nil {
			return
		}
		resp, _ := cbor.Marshal(nsmResponse{
			Version:  1,
			Response: nsmResponsePayload{Error: 5}, // IO_ERROR
		})
		_ = writeFrame(server, resp)
	}()

	d := &nsmDevice{conn: client}
	_, err := d.GetAttestationDoc(nil, nil, nil)
	if err == nil || !strings.Contains(err.Error(), "IO_ERROR") {
		t.Fatalf("error = %v, se esperaba IO_ERROR", err)
	}
}

func TestOpenNSMDeviceMissing(t *testing.T) {
	_, err := openNSMDevice("/no/existe/nsm")
	if err == nil {
		t.Fatal("se esperaba error NSM no disponible")
	}
	var uerr *nsmUnavailableError
	if ok := asNSMUnavailable(err, &uerr); !ok {
		t.Errorf("tipo de error = %T", err)
	}
}

func asNSMUnavailable(err error, target **nsmUnavailableError) bool {
	u, ok := err.(*nsmUnavailableError)
	if ok {
		*target = u
	}
	return ok
}

// --- Endpoints ---

func newEnclaveTestConfig(t *testing.T) {
	t.Helper()
	prevCfg, prevProv := activeConfig, attestationProv
	prevGen := transportKeyGenerated
	t.Setenv("WPFE_KEY_MODE", "generate")
	t.Setenv("WPFE_PRIVATE_KEY", "")
	cfg, err := loadSignerConfig()
	if err != nil {
		t.Fatalf("loadSignerConfig: %v", err)
	}
	activeConfig = cfg
	attestationProv = nil
	t.Cleanup(func() {
		activeConfig, attestationProv = prevCfg, prevProv
		transportKeyGenerated = prevGen
	})
}

func TestTransportKeyHandler(t *testing.T) {
	newEnclaveTestConfig(t)

	req := httptest.NewRequest(http.MethodGet, "/v1/transport-key", nil)
	rec := httptest.NewRecorder()
	transportKeyHandler(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	if !strings.Contains(body, "-----BEGIN PUBLIC KEY-----") {
		t.Errorf("body no es SPKI PEM: %.40q", body)
	}
	// Debe coincidir con la SPKI de la clave activa.
	want, err := transportPublicKeyPEM(activeConfig.privateKey)
	if err != nil {
		t.Fatal(err)
	}
	if body != want {
		t.Error("el PEM servido no coincide con la clave activa")
	}
}

func TestTransportKeyHandlerUnconfigured(t *testing.T) {
	prev := activeConfig
	activeConfig = nil
	t.Cleanup(func() { activeConfig = prev })

	rec := httptest.NewRecorder()
	transportKeyHandler(rec, httptest.NewRequest(http.MethodGet, "/v1/transport-key", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("status = %d", rec.Code)
	}
}

func TestAttestationHandlerBindsActivePublicKey(t *testing.T) {
	newEnclaveTestConfig(t)

	stub := &stubAttestation{doc: []byte("CBOR-DOC")}
	attestationProv = stub
	t.Cleanup(func() { attestationProv = nil })

	nonceRaw := []byte("nonce-fresco-123")
	nonceB64 := "b64:" + base64.StdEncoding.EncodeToString(nonceRaw)

	rec := httptest.NewRecorder()
	attestationHandler(rec, httptest.NewRequest(http.MethodGet, "/v1/attestation?nonce="+nonceB64, nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), base64.StdEncoding.EncodeToString([]byte("CBOR-DOC"))) {
		t.Errorf("body = %s", rec.Body.String())
	}
	wantDER, err := transportPublicKeyDER(activeConfig.privateKey)
	if err != nil {
		t.Fatal(err)
	}
	if string(stub.pk) != string(wantDER) {
		t.Error("el public_key entregado al NSM no coincide con la clave de transporte activa")
	}
	if string(stub.nonce) != string(nonceRaw) {
		t.Errorf("nonce = %q", stub.nonce)
	}
	if !strings.Contains(string(stub.ud), "facturae-signer/") {
		t.Errorf("user_data = %q", stub.ud)
	}
}

func TestAttestationHandlerModes(t *testing.T) {
	newEnclaveTestConfig(t)

	// Sin NSM -> 501
	rec := httptest.NewRecorder()
	attestationHandler(rec, httptest.NewRequest(http.MethodGet, "/v1/attestation", nil))
	if rec.Code != http.StatusNotImplemented {
		t.Errorf("sin NSM: status = %d, se esperaba 501", rec.Code)
	}

	// Nonce demasiado largo -> 400
	attestationProv = &stubAttestation{doc: []byte("d")}
	t.Cleanup(func() { attestationProv = nil })
	long := "b64:" + base64.StdEncoding.EncodeToString(make([]byte, 513))
	rec = httptest.NewRecorder()
	attestationHandler(rec, httptest.NewRequest(http.MethodGet, "/v1/attestation?nonce="+long, nil))
	if rec.Code != http.StatusBadRequest {
		t.Errorf("nonce largo: status = %d, se esperaba 400", rec.Code)
	}

	// Sin configurar -> 503
	activeConfig = nil
	rec = httptest.NewRecorder()
	attestationHandler(rec, httptest.NewRequest(http.MethodGet, "/v1/attestation", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("sin clave: status = %d, se esperaba 503", rec.Code)
	}
}

// --- Aviso de rotación ---

func TestWpfeDecryptErrorRotationHint(t *testing.T) {
	prev := transportKeyGenerated
	t.Cleanup(func() { transportKeyGenerated = prev })

	base := errWPFE1Unwrap

	transportKeyGenerated = false
	if got := wpfeDecryptError(base); got != base {
		t.Errorf("sin generate el error no debe cambiar: %v", got)
	}

	transportKeyGenerated = true
	got := wpfeDecryptError(base)
	if got == base || !strings.Contains(got.Error(), "rotación") || !strings.Contains(got.Error(), "certificado") {
		t.Errorf("aviso de rotación ausente: %v", got)
	}
	if !strings.Contains(got.Error(), base.Error()) {
		t.Errorf("el error original debe conservarse: %v", got)
	}
	if wpfeDecryptError(nil) != nil {
		t.Error("nil debe seguir siendo nil")
	}
}

// --- Firma con clave generada (E2E del modo generate) ---

func TestSignHandlerWithGeneratedKeyMode(t *testing.T) {
	newEnclaveTestConfig(t)

	// Bundle real + blob cifrado con la PÚBLICA de la clave generada (lo que
	// haría WordPress tras pegar el PEM de /v1/transport-key).
	signKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	material, err := mkKeyBundlePEM(t, signKey, mkSelfSignedCert(t, signKey))
	if err != nil {
		t.Fatal(err)
	}
	blob := encryptWPFE1(t, material, &activeConfig.privateKey.PublicKey)
	body, err := json.Marshal(map[string]string{
		"xml":         base64.StdEncoding.EncodeToString([]byte(sampleInvoice)),
		"certificate": base64.StdEncoding.EncodeToString(blob),
	})
	if err != nil {
		t.Fatal(err)
	}

	setActiveConfig(t, activeConfig)
	rec := postSign(t, string(body))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "signed_xml") {
		t.Errorf("respuesta = %s", rec.Body.String())
	}
}

func TestSignHandlerReportsKeyRotation(t *testing.T) {
	newEnclaveTestConfig(t)

	// Blob cifrado con una clave ANTIGUA distinta de la activa.
	old, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	blob := encryptWPFE1(t, []byte("material-bundle"), &old.PublicKey)
	body, err := json.Marshal(map[string]string{
		"xml":         base64.StdEncoding.EncodeToString([]byte(sampleInvoice)),
		"certificate": base64.StdEncoding.EncodeToString(blob),
	})
	if err != nil {
		t.Fatal(err)
	}

	setActiveConfig(t, activeConfig)
	rec := postSign(t, string(body))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "rotación") {
		t.Errorf("falta el aviso de rotación: %s", rec.Body.String())
	}
}
