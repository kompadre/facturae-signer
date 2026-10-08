package main

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

const (
	dsigNS  = "http://www.w3.org/2000/09/xmldsig#"
	maxBody = 10 << 20
)

type signRequest struct {
	XML         string `json:"xml"`
	Certificate string `json:"certificate"`
}

type signResponse struct {
	SignedXML string `json:"signed_xml"`
}

type pdfRequest struct {
	XML string `json:"xml"`
}

type verifactuAltaRequest struct {
	Certificate string          `json:"certificate"`
	Record      verifactuRecord `json:"record"`
}

type verifactuConsultaRequest struct {
	Certificate     string                `json:"certificate"`
	NIF             string                `json:"nif"`
	Nombre          string                `json:"nombre"`
	Fecha           string                `json:"fecha"` // YYYY-MM-DD
	Numero          string                `json:"numero,omitempty"`
	ClavePaginacion *verifactuIDFacturaBC `json:"clave_paginacion,omitempty"`
}

type verifactuLineaJSON struct {
	EmisorNIF   string `json:"emisor_nif"`
	NumSerie    string `json:"num_serie"`
	Fecha       string `json:"fecha"`
	Operacion   string `json:"operacion,omitempty"`
	Estado      string `json:"estado"`
	Codigo      string `json:"codigo,omitempty"`
	Descripcion string `json:"descripcion,omitempty"`
	Duplicado   bool   `json:"duplicado"`
}

type verifactuAltaResult struct {
	EstadoEnvio       string               `json:"estado_envio,omitempty"`
	CSV               string               `json:"csv,omitempty"`
	Deferred          bool                 `json:"deferred"`
	RetryAfterSeconds int                  `json:"retry_after_seconds,omitempty"`
	NIFPresentador    string               `json:"nif_presentador,omitempty"`
	Timestamp         string               `json:"timestamp,omitempty"`
	Lineas            []verifactuLineaJSON `json:"lineas,omitempty"`
	Huella            string               `json:"huella"`
	FechaHoraGen      string               `json:"fecha_hora_gen"`
	Endpoint          string               `json:"endpoint"`
	RawXML            string               `json:"raw_xml,omitempty"` // base64, diagnóstico
}

type verifactuConsultaRegistroJSON struct {
	EmisorNIF   string `json:"emisor_nif"`
	NumSerie    string `json:"num_serie"`
	Fecha       string `json:"fecha"`
	Estado      string `json:"estado"`
	Codigo      string `json:"codigo,omitempty"`
	Descripcion string `json:"descripcion,omitempty"`
}

type verifactuConsultaResult struct {
	ResultadoConsulta string                          `json:"resultado_consulta,omitempty"`
	IndPagina         string                          `json:"ind_pagina"`                 // S = hay más páginas
	ClavePaginacion   *verifactuIDFacturaBC           `json:"clave_paginacion,omitempty"` // para pedir la siguiente
	Registros         []verifactuConsultaRegistroJSON `json:"registros"`
	Endpoint          string                          `json:"endpoint"`
	RawXML            string                          `json:"raw_xml,omitempty"` // base64, diagnóstico
}

type errorResponse struct {
	Error string `json:"error"`
}

// activeConfig se carga del entorno al arrancar; nil significa "sin configurar".
var activeConfig *signerConfig

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

func signHandler(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBody))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, errorResponse{Error: "cuerpo ilegible o demasiado grande"})
		return
	}

	var req signRequest
	if err := json.Unmarshal(body, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, errorResponse{Error: "json inválido"})
		return
	}

	if req.XML == "" {
		writeJSON(w, http.StatusBadRequest, errorResponse{Error: "falta el campo xml"})
		return
	}

	xmlBytes, err := base64.StdEncoding.DecodeString(req.XML)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, errorResponse{Error: "xml no es base64 válido"})
		return
	}

	if req.Certificate == "" {
		writeJSON(w, http.StatusBadRequest, errorResponse{Error: "falta el campo certificate"})
		return
	}

	certBytes, err := base64.StdEncoding.DecodeString(req.Certificate)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, errorResponse{Error: "certificate no es base64 válido"})
		return
	}

	if activeConfig == nil {
		writeJSON(w, http.StatusServiceUnavailable, errorResponse{Error: "servicio sin configurar: falta WPFE_PRIVATE_KEY"})
		return
	}

	material, err := decryptWPFE1(certBytes, activeConfig.privateKey)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, errorResponse{Error: wpfeDecryptError(err).Error()})
		return
	}

	bundle, err := parseKeyBundle(material)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, errorResponse{Error: err.Error()})
		return
	}

	signed, err := signXML(string(xmlBytes), bundle.signing)
	if err != nil {
		var ie *inputError
		var ve *verificationError
		switch {
		case errors.As(err, &ie):
			writeJSON(w, http.StatusBadRequest, errorResponse{Error: ie.Error()})
		case errors.As(err, &ve):
			log.Printf("error de autocomprobación de firma: %v", ve.err)
			writeJSON(w, http.StatusInternalServerError, errorResponse{Error: ve.Error()})
		default:
			writeJSON(w, http.StatusInternalServerError, errorResponse{Error: err.Error()})
		}
		return
	}

	writeJSON(w, http.StatusOK, signResponse{
		SignedXML: base64.StdEncoding.EncodeToString([]byte(signed)),
	})
}

func healthHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = io.WriteString(w, "ok\n")
}

// pdfHandler renderiza el PDF VERI*FACTU de una factura Facturae:
// POST {xml: base64} -> application/pdf. No requiere certificado.
func pdfHandler(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBody))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, errorResponse{Error: "cuerpo ilegible o demasiado grande"})
		return
	}

	var req pdfRequest
	if err := json.Unmarshal(body, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, errorResponse{Error: "json inválido"})
		return
	}
	if req.XML == "" {
		writeJSON(w, http.StatusBadRequest, errorResponse{Error: "falta el campo xml"})
		return
	}

	xmlBytes, err := base64.StdEncoding.DecodeString(req.XML)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, errorResponse{Error: "xml no es base64 válido"})
		return
	}

	model, err := parseInvoicePDFModel(xmlBytes)
	if err != nil {
		var ie *inputError
		if errors.As(err, &ie) {
			writeJSON(w, http.StatusBadRequest, errorResponse{Error: ie.Error()})
		} else {
			writeJSON(w, http.StatusInternalServerError, errorResponse{Error: err.Error()})
		}
		return
	}

	pdf, err := renderInvoicePDF(model)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, errorResponse{Error: err.Error()})
		return
	}

	w.Header().Set("Content-Type", "application/pdf")
	w.Header().Set("Content-Length", fmt.Sprint(len(pdf)))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(pdf)
}

// verifactuAltaHandler da de alta (o anula) un registro de facturación en la
// AEAT: POST {certificate: wpfe1, record: {...}} -> JSON con EstadoEnvio/CSV.
// Autenticación mTLS con el certificado del request; endpoint por entorno.
func verifactuAltaHandler(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBody))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, errorResponse{Error: "cuerpo ilegible o demasiado grande"})
		return
	}
	var req verifactuAltaRequest
	if err := json.Unmarshal(body, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, errorResponse{Error: "json inválido"})
		return
	}
	if req.Certificate == "" {
		writeJSON(w, http.StatusBadRequest, errorResponse{Error: "falta el campo certificate"})
		return
	}

	client, ok := verifactuClientFor(w, req.Certificate)
	if !ok {
		return
	}

	inner, huella, fechaHoraGen, err := buildVerifactuInner(&req.Record, time.Now())
	if err != nil {
		writeVerifactuError(w, err)
		return
	}

	endpoint := verifactuEndpoint()
	raw, err := postVerifactuSOAP(client, endpoint, inner)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, errorResponse{Error: err.Error()})
		return
	}

	resp, err := parseAltaResponse(raw)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, errorResponse{Error: err.Error()})
		return
	}

	result := mapAltaResponse(resp, huella, fechaHoraGen, endpoint, raw)
	writeJSON(w, http.StatusOK, result)
}

// mapAltaResponse traduce la respuesta de la AEAT al JSON del plugin.
//
// TiempoEsperaEnvio es además un límite de tasa: AEAT lo envía JUNTO con un
// veredicto final (EstadoEnvio/RespuestaLinea). Sólo cuenta como "deferred"
// cuando todavía no hay veredicto que procesar (sino se enmascararía un
// "Incorrecto" como "pendiente").
func mapAltaResponse(resp *vfAltaResponse, huella, fechaHoraGen, endpoint string, raw []byte) verifactuAltaResult {
	result := verifactuAltaResult{
		EstadoEnvio:    resp.EstadoEnvio,
		CSV:            resp.CSV,
		NIFPresentador: resp.DatosPresentacion.NIFPresentador,
		Timestamp:      resp.DatosPresentacion.TimestampPresentacion,
		Huella:         huella,
		FechaHoraGen:   fechaHoraGen,
		Endpoint:       endpoint,
		RawXML:         base64.StdEncoding.EncodeToString(raw),
	}
	hasVerdict := resp.EstadoEnvio != "" || len(resp.RespuestaLinea) > 0
	if !hasVerdict && resp.TiempoEsperaEnvio != "" {
		if secs, err := strconv.Atoi(resp.TiempoEsperaEnvio); err == nil {
			result.Deferred = true
			result.RetryAfterSeconds = secs
		}
	}
	for _, ln := range resp.RespuestaLinea {
		result.Lineas = append(result.Lineas, verifactuLineaJSON{
			EmisorNIF:   ln.IDEmisorFactura,
			NumSerie:    ln.NumSerieFactura,
			Fecha:       ln.FechaExpedicionFactura,
			Operacion:   ln.Operacion.TipoOperacion,
			Estado:      ln.EstadoRegistro,
			Codigo:      ln.Codigo,
			Descripcion: ln.Descripcion,
			Duplicado:   ln.RegistroDuplicado != nil,
		})
	}
	return result
}

// verifactuConsultaHandler consulta el estado de registros presentados
// (ConsultaFactuSistemaFacturacion).
func verifactuConsultaHandler(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBody))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, errorResponse{Error: "cuerpo ilegible o demasiado grande"})
		return
	}
	var req verifactuConsultaRequest
	if err := json.Unmarshal(body, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, errorResponse{Error: "json inválido"})
		return
	}
	if req.Certificate == "" {
		writeJSON(w, http.StatusBadRequest, errorResponse{Error: "falta el campo certificate"})
		return
	}

	client, ok := verifactuClientFor(w, req.Certificate)
	if !ok {
		return
	}

	inner, err := buildVerifactuConsulta(req.NIF, req.Nombre, req.Fecha, req.Numero, req.ClavePaginacion)
	if err != nil {
		writeVerifactuError(w, err)
		return
	}

	endpoint := verifactuEndpoint()
	raw, err := postVerifactuSOAP(client, endpoint, inner)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, errorResponse{Error: err.Error()})
		return
	}
	resp, err := parseConsultaResponse(raw)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, errorResponse{Error: err.Error()})
		return
	}

	ind := resp.IndicadorPaginacion
	if ind == "" {
		ind = "N"
	}
	result := verifactuConsultaResult{
		ResultadoConsulta: resp.ResultadoConsulta,
		IndPagina:         ind,
		Endpoint:          endpoint,
		RawXML:            base64.StdEncoding.EncodeToString(raw),
	}
	if resp.ClavePaginacion != nil {
		result.ClavePaginacion = &verifactuIDFacturaBC{
			EmisorNIF: resp.ClavePaginacion.EmisorNIF,
			NumSerie:  resp.ClavePaginacion.NumSerie,
			Fecha:     resp.ClavePaginacion.Fecha,
		}
	}
	for _, reg := range resp.Registros {
		result.Registros = append(result.Registros, verifactuConsultaRegistroJSON{
			EmisorNIF:   reg.IDEmisorFactura,
			NumSerie:    reg.NumSerieFactura,
			Fecha:       reg.FechaExpedicionFactura,
			Estado:      reg.EstadoRegistro.Estado,
			Codigo:      reg.EstadoRegistro.Codigo,
			Descripcion: reg.EstadoRegistro.Descripcion,
		})
	}
	writeJSON(w, http.StatusOK, result)
}

// loadExtraRoots carga CAs adicionales (PEM) desde VERIFACTU_EXTRA_CA para
// confiar en cadenas privadas o en el servidor de pruebas local.
func loadExtraRoots() []*x509.Certificate {
	path := os.Getenv("VERIFACTU_EXTRA_CA")
	if path == "" {
		return nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var certs []*x509.Certificate
	for rest := data; ; {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		c, err := x509.ParseCertificate(block.Bytes)
		if err == nil {
			certs = append(certs, c)
		}
	}
	return certs
}

// verifactuClientFor descifra el bundle de clave WPFE1 y construye el cliente
// mTLS. Escribe el error JSON y devuelve ok=false si falla.
func verifactuClientFor(w http.ResponseWriter, certB64 string) (*http.Client, bool) {
	if activeConfig == nil {
		writeJSON(w, http.StatusServiceUnavailable, errorResponse{Error: "servicio sin configurar: falta WPFE_PRIVATE_KEY"})
		return nil, false
	}
	certBytes, err := base64.StdEncoding.DecodeString(certB64)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, errorResponse{Error: "certificate no es base64 válido"})
		return nil, false
	}
	material, err := decryptWPFE1(certBytes, activeConfig.privateKey)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, errorResponse{Error: wpfeDecryptError(err).Error()})
		return nil, false
	}
	bundle, err := parseKeyBundle(material)
	if err != nil {
		writeVerifactuError(w, err)
		return nil, false
	}
	client, err := newVerifactuClient(bundle, loadExtraRoots(), 60*time.Second)
	if err != nil {
		writeVerifactuError(w, err)
		return nil, false
	}
	return client, true
}

func writeVerifactuError(w http.ResponseWriter, err error) {
	var ie *inputError
	if errors.As(err, &ie) {
		writeJSON(w, http.StatusBadRequest, errorResponse{Error: ie.Error()})
		return
	}
	writeJSON(w, http.StatusInternalServerError, errorResponse{Error: err.Error()})
}

func requireMethod(method string, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != method {
			writeJSON(w, http.StatusMethodNotAllowed, errorResponse{Error: "método no permitido"})
			return
		}
		next(w, r)
	}
}

func newMux() *http.ServeMux {
	mux := http.NewServeMux()
	// Las cuatro rutas de negocio reciben TODO su cuerpo dentro del
	// envoltorio WPFE1 (ver envelope.go); /health y /v1/* quedan fuera:
	// son sonda y material público respectivamente.
	mux.HandleFunc("/sign", requireMethod(http.MethodPost, envelopeMiddleware(signHandler)))
	mux.HandleFunc("/pdf", requireMethod(http.MethodPost, envelopeMiddleware(pdfHandler)))
	mux.HandleFunc("/verifactu/alta", requireMethod(http.MethodPost, envelopeMiddleware(verifactuAltaHandler)))
	mux.HandleFunc("/verifactu/consulta", requireMethod(http.MethodPost, envelopeMiddleware(verifactuConsultaHandler)))
	mux.HandleFunc("/health", requireMethod(http.MethodGet, healthHandler))
	mux.HandleFunc("/v1/info", requireMethod(http.MethodGet, infoHandler))
	mux.HandleFunc("/v1/transport-key", requireMethod(http.MethodGet, transportKeyHandler))
	mux.HandleFunc("/v1/attestation", requireMethod(http.MethodGet, attestationHandler))
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusNotFound, errorResponse{Error: "ruta no encontrada"})
	})
	return mux
}

type statusWriter struct {
	http.ResponseWriter
	status int
}

func (sw *statusWriter) WriteHeader(code int) {
	sw.status = code
	sw.ResponseWriter.WriteHeader(code)
}

func logging(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		sw := &statusWriter{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(sw, r)
		log.Printf("%s %s -> %d (%s)", r.Method, r.URL.Path, sw.status, time.Since(start).Round(time.Millisecond))
	})
}

func main() {
	cfg, err := loadSignerConfig()
	if err != nil {
		log.Printf("AVISO: firma deshabilitada: %v", err)
	} else {
		activeConfig = cfg
		if cfg.generated {
			log.Printf("firma habilitada (clave de transporte GENERADA en memoria; pública en /v1/transport-key)")
		} else {
			log.Printf("firma habilitada (bundle PEM por petición; sin contraseña de PKCS#12)")
		}
	}

	// Attestation: NSM real si existe /dev/nsm; sin él, los endpoints de
	// /v1/* responden 501 (modo docker).
	if prov, err := openNSMDevice(os.Getenv("NSM_DEVICE")); err == nil {
		attestationProv = prov
		log.Printf("NSM disponible: attestation habilitado")
	} else {
		log.Printf("AVISO: %v (attestation deshabilitado)", err)
	}

	spec, err := parseListen(os.Getenv("LISTEN"))
	if err != nil {
		log.Fatal(err)
	}
	relaySpec := os.Getenv("VSOCK_OUTBOUND")
	if spec.network == "vsock" && strings.TrimSpace(relaySpec) == "" {
		relaySpec = "3:9001" // CID del parent por defecto
	}
	relay, err := parseRelay(relaySpec)
	if err != nil {
		log.Fatal(err)
	}
	outboundRelay = relay
	if relay != nil {
		log.Printf("salida a AEAT vía relay vsock cid=%d puerto=%d", relay.cid, relay.port)
	}

	ln, err := serveListener(spec)
	if err != nil {
		log.Fatal(err)
	}

	srv := &http.Server{
		Handler:           logging(newMux()),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	log.Printf("facturae-signer escuchando en %s:%s (v=%s)", spec.network, spec.addr, version)
	log.Fatal(srv.Serve(ln))
}
