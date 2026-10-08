package main

import (
	"bytes"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"

	"facturae-signer/internal/keystore"
)

// ContentType del envoltorio de respuesta (sólo si WPFE_SEAL_RESPONSES=1).
const envelopeContentType = "application/vnd.facturae.wpfe1"

// envFlag devuelve true si la variable vale "1"/"true".
func envFlag(name string) bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(name))) {
	case "1", "true", "yes", "on":
		return true
	}
	return false
}

// sealResponses: la respuesta vuelve sellada con la MISMA clave AES que trajo
// el request (el cliente no necesita pareja propia). Desactivado por defecto:
// el XML firmado ya lleva su XAdES y el tramo local se depura más cómodo en
// claro. Opt-in listo: WPFE_SEAL_RESPONSES=1.
func sealResponses() bool { return envFlag("WPFE_SEAL_RESPONSES") }

// requireEnvelope: en el VPS se puede exigir que TODO cuerpo venga en el
// envoltorio WPFE1 (los clientes viejos en claro recibirán 400 en lugar de
// procesarse). Por defecto off para no romper staging (modo env).
func requireEnvelope() bool { return envFlag("WPFE_REQUIRE_ENVELOPE") }

// envelopeMiddleware descifra el cuerpo antes de que lo lean los handlers.
//
//   - Cuerpo WPFE1  → se abre, el handler ve el JSON en claro y (si
//     WPFE_SEAL_RESPONSES=1) la respuesta se sella con la misma clave AES.
//   - Cuerpo JSON en claro → pasa tal cual, salvo WPFE_REQUIRE_ENVELOPE=1.
//
// Así el contrato de "toda la entrada cifrada con la clave de transporte
// larga" se cumple en la puerta, con un solo formato (el mismo que ya usa
// el campo certificate) y sin tocar los handlers.
func envelopeMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.Body == nil {
			next(w, r)
			return
		}

		raw, err := io.ReadAll(io.LimitReader(r.Body, maxBody+1))
		if err != nil {
			writeJSON(w, http.StatusBadRequest, errorResponse{Error: "cuerpo ilegible o demasiado grande"})
			return
		}
		if int64(len(raw)) > maxBody {
			writeJSON(w, http.StatusRequestEntityTooLarge, errorResponse{Error: "cuerpo ilegible o demasiado grande"})
			return
		}
		if len(bytes.TrimSpace(raw)) == 0 {
			next(w, r)
			return
		}

		if !bytes.HasPrefix(raw, []byte("WPFE1")) {
			if requireEnvelope() {
				writeJSON(w, http.StatusBadRequest, errorResponse{
					Error: "cuerpo sin envoltorio WPFE1 (el signer exige WPFE_REQUIRE_ENVELOPE=1)",
				})
				return
			}
			// Cliente legado / staging: JSON en claro.
			r.Body = io.NopCloser(bytes.NewReader(raw))
			r.ContentLength = int64(len(raw))
			next(w, r)
			return
		}

		if activeConfig == nil {
			writeJSON(w, http.StatusServiceUnavailable, errorResponse{Error: "servicio sin configurar: falta la clave de transporte"})
			return
		}

		plain, aesKey, err := openWPFE1(raw, activeConfig.privateKey)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, errorResponse{Error: wpfeDecryptError(err).Error()})
			return
		}
		// Los buffers sensibles se limpian al salir: la clave AES en claro y
		// el JSON recién abierto (lleva el bundle con la clave privada del
		// usuario; Go no puede limpiar strings, pero sí estos []byte).
		defer keystore.Zero(plain)
		defer keystore.Zero(aesKey)

		r.Body = io.NopCloser(bytes.NewReader(plain))
		r.ContentLength = int64(len(plain))

		if !sealResponses() {
			next(w, r)
			return
		}

		buf := &bufferedResponse{header: w.Header(), status: http.StatusOK}
		next(buf, r)

		sealed, err := sealWPFE1WithKey(buf.body, aesKey, &activeConfig.privateKey.PublicKey)
		if err != nil {
			// Mejor un 500 que una respuesta en claro que el cliente espera
			// sellada: no se firma nada con datos a medias.
			writeJSON(w, http.StatusInternalServerError, errorResponse{Error: "no se pudo sellar la respuesta: " + err.Error()})
			return
		}
		w.Header().Set("Content-Type", envelopeContentType)
		w.Header().Set("Content-Length", strconv.Itoa(len(sealed)))
		w.WriteHeader(buf.status)
		_, _ = w.Write(sealed)
	}
}

// bufferedResponse acumula la salida del handler para sellarla al terminar.
type bufferedResponse struct {
	header http.Header
	status int
	body   []byte
	wrote  bool
}

func (b *bufferedResponse) Header() http.Header { return b.header }

func (b *bufferedResponse) WriteHeader(status int) {
	if b.wrote {
		return
	}
	b.status = status
	b.wrote = true
}

func (b *bufferedResponse) Write(p []byte) (int, error) {
	if !b.wrote {
		b.WriteHeader(http.StatusOK)
	}
	b.body = append(b.body, p...)
	return len(p), nil
}

// infoHandler describe las capacidades del nodo para que el cliente negocie:
// envoltorio, sellado de respuesta, modo de clave y presencia de vínculo.
//
//	GET /v1/info
func infoHandler(w http.ResponseWriter, r *http.Request) {
	keyMode := ""
	binding := false
	if activeConfig != nil {
		keyMode = activeConfig.keyMode
		binding = activeConfig.host != nil
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"version":          version,
		"key_mode":         keyMode,
		"envelope":         "wpfe1",
		"seal_responses":   sealResponses(),
		"require_envelope": requireEnvelope(),
		"binding":          binding,
		"attestation":      attestationProv != nil,
	})
}
