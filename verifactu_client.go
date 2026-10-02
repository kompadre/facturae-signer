package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"software.sslmate.com/src/go-pkcs12"
)

// verifactuEndpoint devuelve la URL del servicio VerifactuSOAP.
//
//	VERIFACTU_ENDPOINT  URL completa (tiene prioridad).
//	VERIFACTU_ENV       "production" -> www1/www10; otro valor -> prewww1/prewww10 (sandbox).
//	VERIFACTU_SELLO     "1"/"true" -> variante de sello (www10/prewww10).
func verifactuEndpoint() string {
	if e := os.Getenv("VERIFACTU_ENDPOINT"); e != "" {
		return e
	}
	host := "prewww1.aeat.es"
	if os.Getenv("VERIFACTU_ENV") == "production" {
		host = "www1.agenciatributaria.gob.es"
	}
	if v := os.Getenv("VERIFACTU_SELLO"); v == "1" || strings.EqualFold(v, "true") {
		if strings.HasSuffix(host, "aeat.es") { // sandbox
			host = "prewww10.aeat.es"
		} else {
			host = "www10.agenciatributaria.gob.es"
		}
	}
	return "https://" + host + "/wlpl/TIKE-CONT/ws/SistemaFacturacion/VerifactuSOAP"
}

// newVerifactuClient construye el cliente HTTP mTLS a partir del contenedor
// PKCS#12 (descifrado del blob WPFE1). extraRoots se añade al almacén del
// sistema (para pruebas con CA propia).
func newVerifactuClient(p12 []byte, password string, extraRoots []*x509.Certificate, timeout time.Duration) (*http.Client, error) {
	key, leaf, caCerts, err := pkcs12.DecodeChain(p12, password)
	if err != nil {
		return nil, inputErrf("PKCS#12 ilegible o contraseña incorrecta: %v", err)
	}
	if leaf == nil {
		return nil, inputErrf("el PKCS#12 no contiene certificado")
	}

	cert := tls.Certificate{
		Certificate: [][]byte{leaf.Raw},
		PrivateKey:  key,
		Leaf:        leaf,
	}
	for _, ca := range caCerts {
		cert.Certificate = append(cert.Certificate, ca.Raw)
	}

	rootCAs, err := x509.SystemCertPool()
	if err != nil || rootCAs == nil {
		rootCAs = x509.NewCertPool()
	}
	for _, ca := range extraRoots {
		rootCAs.AddCert(ca)
	}

	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				Certificates: []tls.Certificate{cert},
				RootCAs:      rootCAs,
				MinVersion:   tls.VersionTLS12,
			},
		},
	}, nil
}

// postVerifactuSOAP envuelve el XML interno en un SOAP 1.1 (document/literal,
// SOAPAction "") y hace POST. Devuelve el cuerpo de la respuesta.
func postVerifactuSOAP(client *http.Client, endpoint, inner string) ([]byte, error) {
	envelope := `<?xml version="1.0" encoding="UTF-8"?>` +
		`<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">` +
		`<soapenv:Header/>` +
		`<soapenv:Body>` + inner + `</soapenv:Body>` +
		`</soapenv:Envelope>`

	req, err := http.NewRequest(http.MethodPost, endpoint, strings.NewReader(envelope))
	if err != nil {
		return nil, fmt.Errorf("construir petición: %w", err)
	}
	req.Header.Set("Content-Type", "text/xml; charset=utf-8")
	req.Header.Set("SOAPAction", `""`)

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("envío a la AEAT: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return nil, fmt.Errorf("lectura de respuesta: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("la AEAT devolvió HTTP %d: %s", resp.StatusCode, snippet(body))
	}
	return body, nil
}

func snippet(b []byte) string {
	s := strings.TrimSpace(string(b))
	if len(s) > 300 {
		return s[:300] + "…"
	}
	return s
}

// --- Parseo de respuestas (encoding/xml por nombre local: ignora prefijos) ---

type vfRespuestaLinea struct {
	IDEmisorFactura        string `xml:"IDFactura>IDEmisorFactura"`
	NumSerieFactura        string `xml:"IDFactura>NumSerieFactura"`
	FechaExpedicionFactura string `xml:"IDFactura>FechaExpedicionFactura"`
	// En la respuesta de ALTA, Operacion es un bloque con TipoOperacion y
	// EstadoRegistro/Codigo/Descripcion son hojas planas (en la CONSULTA el
	// EstadoRegistro sí es un bloque anidado — ver vfConsultaRegistro).
	Operacion struct {
		TipoOperacion string `xml:"TipoOperacion"`
	} `xml:"Operacion"`
	EstadoRegistro    string `xml:"EstadoRegistro"`
	Codigo            string `xml:"CodigoErrorRegistro"`
	Descripcion       string `xml:"DescripcionErrorRegistro"`
	RegistroDuplicado *struct {
		IDEmisorFactura string `xml:"IDFactura>IDEmisorFactura"`
	} `xml:"RegistroDuplicado"`
}

type vfAltaResponse struct {
	TiempoEsperaEnvio string `xml:"TiempoEsperaEnvio"`
	EstadoEnvio       string `xml:"EstadoEnvio"`
	CSV               string `xml:"CSV"`
	DatosPresentacion struct {
		NIFPresentador        string `xml:"NIFPresentador"`
		TimestampPresentacion string `xml:"TimestampPresentacion"`
	} `xml:"DatosPresentacion"`
	RespuestaLinea []vfRespuestaLinea `xml:"RespuestaLinea"`
}

type vfConsultaRegistro struct {
	IDEmisorFactura        string `xml:"IDFactura>IDEmisorFactura"`
	NumSerieFactura        string `xml:"IDFactura>NumSerieFactura"`
	FechaExpedicionFactura string `xml:"IDFactura>FechaExpedicionFactura"`
	EstadoRegistro         struct {
		Estado      string `xml:"EstadoRegistro"`
		Codigo      string `xml:"CodigoErrorRegistro"`
		Descripcion string `xml:"DescripcionErrorRegistro"`
	} `xml:"EstadoRegistro"`
}

type vfConsultaResponse struct {
	ResultadoConsulta string               `xml:"ResultadoConsulta"`
	Registros         []vfConsultaRegistro `xml:"RegistroRespuestaConsultaFactuSistemaFacturacion"`
}

type soapFaultDetail struct {
	Faultcode   string `xml:"faultcode"`
	Faultstring string `xml:"faultstring"`
}

// soapEnvelope envuelve la carga útil: las respuestas AEAT llegan dentro de
// soapenv:Envelope/soapenv:Body (encoding/xml exige recorrer la estructura).
type soapEnvelope struct {
	XMLName xml.Name
	Body    struct {
		Fault    *soapFaultDetail    `xml:"Fault"`
		Alta     *vfAltaResponse     `xml:"RespuestaRegFactuSistemaFacturacion"`
		Consulta *vfConsultaResponse `xml:"RespuestaConsultaFactuSistemaFacturacion"`
	} `xml:"Body"`
}

func parseSoapEnvelope(body []byte) (*soapEnvelope, error) {
	var env soapEnvelope
	if err := xml.Unmarshal(body, &env); err != nil {
		return nil, fmt.Errorf("respuesta no parseable: %w", err)
	}
	if env.Body.Fault != nil {
		return nil, fmt.Errorf("SOAP Fault: %s: %s", env.Body.Fault.Faultcode, env.Body.Fault.Faultstring)
	}
	return &env, nil
}

// parseAltaResponse devuelve los campos clave de RespuestaRegFactuSistemaFacturacion.
// TiempoEsperaEnvio != "" cuando AEAT pide esperar (deferred).
func parseAltaResponse(body []byte) (*vfAltaResponse, error) {
	env, err := parseSoapEnvelope(body)
	if err != nil {
		return nil, err
	}
	if env.Body.Alta == nil {
		return nil, fmt.Errorf("respuesta sin RespuestaRegFactuSistemaFacturacion")
	}
	r := env.Body.Alta
	if r.EstadoEnvio == "" && r.TiempoEsperaEnvio == "" {
		return nil, fmt.Errorf("respuesta sin EstadoEnvio ni TiempoEsperaEnvio")
	}
	return r, nil
}

func parseConsultaResponse(body []byte) (*vfConsultaResponse, error) {
	env, err := parseSoapEnvelope(body)
	if err != nil {
		return nil, err
	}
	if env.Body.Consulta == nil {
		return nil, fmt.Errorf("respuesta sin RespuestaConsultaFactuSistemaFacturacion")
	}
	return env.Body.Consulta, nil
}
