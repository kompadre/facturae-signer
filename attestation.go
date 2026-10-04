package main

import (
	"encoding/base64"
	"io"
	"net/http"
)

// version se inyecta en build con -ldflags "-X main.version=…"; forma parte
// del user_data del documento de attestation (reconocible en el verify).
var version = "dev"

// attestationProv es el proveedor activo (NSM real) o nil (sin /dev/nsm).
var attestationProv attestationProvider

// transportKeyHandler sirve la SPKI PEM de la clave de transporte: lo que hay
// que pegar en Ajustes → Clave Pública. Pública por definición: sin auth.
func transportKeyHandler(w http.ResponseWriter, r *http.Request) {
	if activeConfig == nil {
		writeJSON(w, http.StatusServiceUnavailable, errorResponse{Error: "servicio sin configurar: falta la clave de transporte"})
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

// decodeNonce acepta base64 (std o url, con/sin padding) o bytes crudos.
func decodeNonce(s string) []byte {
	if s == "" {
		return nil
	}
	for _, enc := range []*base64.Encoding{
		base64.StdEncoding, base64.URLEncoding,
		base64.RawStdEncoding, base64.RawURLEncoding,
	} {
		if b, err := enc.DecodeString(s); err == nil {
			return b
		}
	}
	return []byte(s)
}
