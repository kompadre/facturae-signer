package main

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"facturae-signer/internal/hostid"
)

// version se inyecta en build con -ldflags "-X main.version=…"; forma parte
// del user_data del documento de attestation (reconocible en el verify).
var version = "dev"

// attestationProv es el proveedor activo (NSM real) o nil (sin /dev/nsm).
var attestationProv attestationProvider

// transportKeyHandler sirve la SPKI PEM de la clave de transporte: lo que hay
// que pegar en Ajustes → Clave Pública. Pública por definición: sin auth.
//
//	GET /v1/transport-key           → PEM (compatibilidad, lo de siempre)
//	GET /v1/transport-key?format=json → documento de vínculo (ver abajo)
//
// El documento JSON añade la prueba de que ESA pública pertenece a ESTE host:
// la identidad del host firma el vínculo y el cliente lo verifica contra la
// huella que tiene fijada. Un MitM que cambie /etc/hosts sirve su propia
// identidad ⇒ huella distinta ⇒ el cliente rechaza (no hace falta TLS para
// eso, aunque exista y se use).
func transportKeyHandler(w http.ResponseWriter, r *http.Request) {
	if activeConfig == nil {
		writeJSON(w, http.StatusServiceUnavailable, errorResponse{Error: "servicio sin configurar: falta la clave de transporte"})
		return
	}

	if strings.EqualFold(r.URL.Query().Get("format"), "json") {
		transportKeyJSON(w)
		return
	}

	pemStr, err := transportPublicKeyPEM(activeConfig.privateKey)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, errorResponse{Error: "clave pública no disponible"})
		return
	}
	w.Header().Set("Content-Type", "application/x-pem-file; charset=us-ascii")
	w.WriteHeader(http.StatusOK)
	_, _ = io.WriteString(w, pemStr)
}

// transportKeyJSON devuelve el documento de vínculo.
//
// Receta de verificación del cliente (el payload se RECALCULA, no se confía
// en el que viaja en claro):
//
//	payload = "wpfe-binding/v1" | RawStd(der(transport_key)) | RawStd(der(host_public_key)) | issued_at
//	verificar binding con la clave de host_public_key (openssl_verify SHA-256)
//	y comparar la huella de host_public_key con la fijada en Ajustes.
//
// transport_key / host_public_key son PEM `PUBLIC KEY`: en PHP bastan
// base64_decode del cuerpo para obtener el DER (SPKI) que pide el payload.
func transportKeyJSON(w http.ResponseWriter) {
	doc, err := buildTransportKeyDoc(activeConfig)
	if err != nil {
		if errors.Is(err, errNoHostIdentityDoc) {
			writeJSON(w, http.StatusNotImplemented, errorResponse{
				Error: "sin identidad de host (sólo en WPFE_KEY_MODE=persistent); usa ?format=pem",
			})
			return
		}
		writeJSON(w, http.StatusInternalServerError, errorResponse{Error: err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, doc)
}

// errNoHostIdentityDoc marca el caso "modo env/generate sin identidad": no es
// un fallo del servidor, es que ese modo no publica vínculo.
var errNoHostIdentityDoc = errors.New("sin identidad de host")

// buildTransportKeyDoc construye el documento de vínculo. Lo comparten el
// endpoint HTTP y el CLI (`wpfe-sign pubkey --json`), para que el cliente
// vea exactamente lo mismo venga por socket o por red.
func buildTransportKeyDoc(cfg *signerConfig) (map[string]any, error) {
	if cfg == nil || cfg.privateKey == nil {
		return nil, errors.New("servicio sin configurar: falta la clave de transporte")
	}
	if cfg.host == nil {
		return nil, errNoHostIdentityDoc
	}

	transportSPKI, err := x509.MarshalPKIXPublicKey(&cfg.privateKey.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("clave pública no disponible: %w", err)
	}
	transportPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: transportSPKI})
	hostSPKIPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: cfg.host.SPKI})
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cfg.host.Cert.Raw})

	issuedAt := time.Now().UTC().Truncate(time.Second)
	alg, sig, _, err := cfg.host.SignBinding(transportSPKI, issuedAt)
	if err != nil {
		return nil, fmt.Errorf("no se pudo firmar el vínculo: %w", err)
	}

	return map[string]any{
		"transport_key":    string(transportPEM),
		"transport_key_id": hostid.Fingerprint(transportSPKI),
		"host_cert":        string(certPEM),
		"host_public_key":  string(hostSPKIPEM),
		"host_fingerprint": cfg.host.Fingerprint,
		"binding_alg":      alg,
		"binding":          base64.StdEncoding.EncodeToString(sig),
		"issued_at":        issuedAt.Format(time.RFC3339),
		"key_mode":         cfg.keyMode,
		"version":          version,
	}, nil
}

// attestationHandler devuelve el documento de attestation del NSM con la
// clave de transporte enlazada (campo public_key): cualquiera puede
// verificar que esa pública pertenece a ESTE enclave medido.
//
//	GET /v1/attestation[?nonce=<base64|raw>]
func attestationHandler(w http.ResponseWriter, r *http.Request) {
	if activeConfig == nil {
		writeJSON(w, http.StatusServiceUnavailable, errorResponse{Error: "servicio sin configurar: falta la clave de transporte"})
		return
	}
	if attestationProv == nil {
		writeJSON(w, http.StatusNotImplemented, errorResponse{Error: "sin NSM: el attestation doc sólo está disponible en el enclave (/dev/nsm)"})
		return
	}

	nonce := decodeNonce(r.URL.Query().Get("nonce"))
	if len(nonce) > nsmMaxNonce {
		writeJSON(w, http.StatusBadRequest, errorResponse{Error: "nonce demasiado largo (máx. 512 bytes)"})
		return
	}

	pubDER, err := transportPublicKeyDER(activeConfig.privateKey)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, errorResponse{Error: "clave pública no disponible"})
		return
	}
	userData := []byte("facturae-signer/" + version)

	doc, err := attestationProv.GetAttestationDoc(pubDER, userData, nonce)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, errorResponse{Error: err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{
		"attestation_doc": base64.StdEncoding.EncodeToString(doc),
	})
}

// decodeNonce: "b64:<std>" | "b64url:<url>" | bytes crudos. Los prefijos
// evitan la ambigüedad (un nonce crudo que "parece" base64).
func decodeNonce(s string) []byte {
	if s == "" {
		return nil
	}
	if rest, ok := strings.CutPrefix(s, "b64:"); ok {
		if b, err := base64.StdEncoding.DecodeString(rest); err == nil {
			return b
		}
		return []byte(s)
	}
	if rest, ok := strings.CutPrefix(s, "b64url:"); ok {
		if b, err := base64.RawURLEncoding.DecodeString(rest); err == nil {
			return b
		}
		return []byte(s)
	}
	return []byte(s)
}
