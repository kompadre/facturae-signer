package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

// --- Huella: vectores oficiales de AEAT (spec v0.1.2, ejemplos s6.1-s6.3) ---

func TestHuellaAltaGoldenGenesis(t *testing.T) {
	got := huellaAlta("89890001K", "12345678/G33", "01-01-2024", "F1",
		"12.35", "123.45", "2024-01-01T19:20:30+01:00", "")
	want := "3C464DAF61ACB827C65FDA19F352A4E3BDC2C640E9E9FC4CC058073F38F12F60"
	if got != want {
		t.Errorf("huella génesis = %s, se esperaba %s", got, want)
	}
}

func TestHuellaAltaGoldenChained(t *testing.T) {
	got := huellaAlta("89890001K", "12345679/G34", "01-01-2024", "F1",
		"12.35", "123.45", "2024-01-01T19:20:35+01:00",
		"3C464DAF61ACB827C65FDA19F352A4E3BDC2C640E9E9FC4CC058073F38F12F60")
	want := "F7B94CFD8924EDFF273501B01EE5153E4CE8F259766F88CF6ACB8935802A2B97"
	if got != want {
		t.Errorf("huella encadenada = %s, se esperaba %s", got, want)
	}
}

func TestHuellaAnulacionGolden(t *testing.T) {
	got := huellaAnulacion("89890001K", "12345679/G34", "01-01-2024",
		"2024-01-01T19:20:40+01:00",
		"F7B94CFD8924EDFF273501B01EE5153E4CE8F259766F88CF6ACB8935802A2B97")
	want := "177547C0D57AC74748561D054A9CEC14B4C4EA23D1BEFD6F2E69E3A388F90C68"
	if got != want {
		t.Errorf("huella anulación = %s, se esperaba %s", got, want)
	}
}

// --- Helpers de formato ---

func TestVeriFecha(t *testing.T) {
	got, err := veriFecha("2026-10-01")
	if err != nil || got != "01-10-2026" {
		t.Errorf("veriFecha = %q, %v", got, err)
	}
	if _, err := veriFecha("01/10/2026"); err == nil {
		t.Error("se esperaba error para fecha no ISO")
	}
}

func TestVeriImporte(t *testing.T) {
	cases := map[string]string{
		"12.1":     "12.10",
		"2.665":    "2.67", // HALF_UP
		"0":        "0.00",
		"1234.567": "1234.57",
	}
	for in, want := range cases {
		got, err := veriImporte(in)
		if err != nil || got != want {
			t.Errorf("veriImporte(%q) = %q, %v; se esperaba %q", in, got, err, want)
		}
	}
	if _, err := veriImporte("abc"); err == nil {
		t.Error("se esperaba error para importe no numérico")
	}
}

// --- Constructor del registro ---

func sampleRecord() *verifactuRecord {
	return &verifactuRecord{
		Kind:         "alta",
		EmisorNIF:    "B19995869",
		EmisorNombre: "Empresa de Pruebas S.L.",
		Numero:       "2026-0007",
		Fecha:        "2026-10-01",
		Destinatario: verifactuDestinatario{Nombre: "Bla Prueba", NIF: "B37252301"},
		Detalles: []verifactuDetalle{
			{TipoImpositivo: "21.00", Base: "100.00", Cuota: "21.00"},
		},
		CuotaTotal:   "21.00",
		ImporteTotal: "121.00",
	}
}

func TestBuildVerifactuAltaStructure(t *testing.T) {
	now := time.Date(2026, 10, 1, 12, 0, 0, 0, time.FixedZone("", 3600))
	inner, huella, fechaGen, err := buildVerifactuInner(sampleRecord(), now)
	if err != nil {
		t.Fatalf("build: %v", err)
	}

	if fechaGen != "2026-10-01T12:00:00+01:00" {
		t.Errorf("fecha gen = %q", fechaGen)
	}
	if len(huella) != 64 || huella != strings.ToUpper(huella) {
		t.Errorf("huella = %q", huella)
	}

	// Namespaces: raíz/fila en SuministroLR, registro en SuministroInformacion.
	if !strings.Contains(inner, `xmlns="`+vfLRNS+`"`) {
		t.Error("falta el namespace SuministroLR en la raíz")
	}
	if !strings.Contains(inner, `<RegistroAlta xmlns="`+vfSFNS+`">`) {
		t.Error("RegistroAlta debe declarar el namespace SuministroInformacion")
	}
	// Cabecera es elemento LOCAL de SuministroLR (qualified): sin prefijo
	// hereda LR. Con sf: la AEAT responde 4102 "Falta … Cabecera".
	if !strings.Contains(inner, "<Cabecera>") {
		t.Error("Cabecera debe ir sin prefijo (namespace SuministroLR)")
	}
	if strings.Contains(inner, "<sf:Cabecera>") {
		t.Error("sf:Cabecera está en el namespace equivocado (la AEAT no lo ve)")
	}
	if !strings.Contains(inner, "<sf:ObligadoEmision>") {
		t.Error("los hijos de Cabecera van con prefijo sf (CabeceraType en SuministroInformacion)")
	}
	if !strings.Contains(inner, "<RegistroFactura>") {
		t.Error("RegistroFactura es local de SuministroLR (sin prefijo)")
	}

	// Orden obligatorio de elementos del alta (XSD RegistroFacturacionAltaType).
	order := []string{
		"<IDVersion>", "<IDFactura>", "<NombreRazonEmisor>", "<Subsanacion>",
		"<RechazoPrevio>", "<TipoFactura>", "<DescripcionOperacion>", "<Destinatarios>",
		"<Cupon>", "<Desglose>", "<CuotaTotal>", "<ImporteTotal>", "<Encadenamiento>",
		"<SistemaInformatico>", "<FechaHoraHusoGenRegistro>", "<TipoHuella>", "<Huella>",
	}
	pos := -1
	for _, el := range order {
		p := strings.Index(inner, el)
		if p < 0 {
			t.Fatalf("falta el elemento %s", el)
		}
		if p < pos {
			t.Errorf("el elemento %s está fuera de orden", el)
		}
		pos = p
	}

	for _, want := range []string{
		"<FechaExpedicionFactura>01-10-2026</FechaExpedicionFactura>",
		"<TipoFactura>F1</TipoFactura>",
		"<CalificacionOperacion>S1</CalificacionOperacion>",
		"<BaseImponibleOimporteNoSujeto>100.00</BaseImponibleOimporteNoSujeto>",
		"<CuotaRepercutida>21.00</CuotaRepercutida>",
		"<PrimerRegistro>S</PrimerRegistro>",
		"<IdSistemaInformatico>WP</IdSistemaInformatico>",
		"<TipoHuella>01</TipoHuella>",
		"<sf:NombreRazon>Empresa de Pruebas S.L.</sf:NombreRazon>",
		"<IDDestinatario>",
	} {
		if !strings.Contains(inner, want) {
			t.Errorf("falta %s", want)
		}
	}
	if strings.Contains(inner, "<RegistroAnterior>") {
		t.Error("sin previous no debe llevar RegistroAnterior")
	}
}

func TestBuildVerifactuAltaChained(t *testing.T) {
	rec := sampleRecord()
	rec.Previous = &verifactuPrevious{
		Huella:    "3C464DAF61ACB827C65FDA19F352A4E3BDC2C640E9E9FC4CC058073F38F12F60",
		EmisorNIF: "B19995869",
		Numero:    "2026-0006",
		FechaEs:   "30-09-2026",
	}
	inner, _, _, err := buildVerifactuInner(rec, time.Now())
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	for _, want := range []string{
		"<NumSerieFactura>2026-0006</NumSerieFactura>",
		"<FechaExpedicionFactura>30-09-2026</FechaExpedicionFactura>",
		"<Huella>3C464DAF61ACB827C65FDA19F352A4E3BDC2C640E9E9FC4CC058073F38F12F60</Huella>",
	} {
		if !strings.Contains(inner, want) {
			t.Errorf("falta %s en el encadenamiento", want)
		}
	}
	// Encadenamiento es una elección (XSD): con previous va SOLO RegistroAnterior.
	if strings.Contains(inner, "<PrimerRegistro>") {
		t.Error("con previous no debe llevar PrimerRegistro (choice del XSD)")
	}
}

func TestBuildVerifactuAnulacionStructure(t *testing.T) {
	rec := &verifactuRecord{
		Kind:         "anulacion",
		EmisorNIF:    "B19995869",
		EmisorNombre: "Empresa de Pruebas S.L.",
		Numero:       "2026-0007",
		Fecha:        "2026-10-01",
	}
	inner, huella, _, err := buildVerifactuInner(rec, time.Now())
	if err != nil {
		t.Fatalf("build: %v", err)
	}

	if !strings.Contains(inner, `<RegistroAnulacion xmlns="`+vfSFNS+`">`) {
		t.Error("falta RegistroAnulacion con su namespace")
	}
	for _, want := range []string{
		"<IDEmisorFacturaAnulada>B19995869</IDEmisorFacturaAnulada>",
		"<NumSerieFacturaAnulada>2026-0007</NumSerieFacturaAnulada>",
		"<FechaExpedicionFacturaAnulada>01-10-2026</FechaExpedicionFacturaAnulada>",
	} {
		if !strings.Contains(inner, want) {
			t.Errorf("falta %s", want)
		}
	}
	// El anulador no lleva NombreRazonEmisor ni datos de alta.
	if strings.Contains(inner, "<NombreRazonEmisor>") {
		t.Error("RegistroAnulacion no lleva NombreRazonEmisor")
	}
	if strings.Contains(inner, "<CuotaTotal>") || strings.Contains(inner, "<Destinatarios>") {
		t.Error("RegistroAnulacion no lleva datos de alta")
	}
	if len(huella) != 64 {
		t.Errorf("huella anulación = %q", huella)
	}
}

func TestBuildVerifactuValidation(t *testing.T) {
	cases := []*verifactuRecord{
		{Kind: "otra"},
		{Kind: "alta"}, // sin emisor/numero
		func() *verifactuRecord { r := sampleRecord(); r.Detalles = nil; return r }(),
		func() *verifactuRecord { r := sampleRecord(); r.Fecha = "ayer"; return r }(),
		func() *verifactuRecord { r := sampleRecord(); r.Destinatario = verifactuDestinatario{}; return r }(),
	}
	for i, rec := range cases {
		if _, _, _, err := buildVerifactuInner(rec, time.Now()); err == nil {
			t.Errorf("caso %d: se esperaba error de entrada", i)
		}
	}
}

// --- Consulta ---

func TestBuildVerifactuConsulta(t *testing.T) {
	inner, err := buildVerifactuConsulta("B19995869", "Empresa de Pruebas", "2026-10-01", "2026-0007", nil)
	if err != nil {
		t.Fatalf("consulta: %v", err)
	}
	for _, want := range []string{
		`xmlns="` + vfConsultaNS + `"`,
		"<sf:IDVersion>1.0</sf:IDVersion>",
		"<sf:NIF>B19995869</sf:NIF>",
		"<sf:Ejercicio>2026</sf:Ejercicio>",
		"<sf:Periodo>10</sf:Periodo>",
		"<NumSerieFactura>2026-0007</NumSerieFactura>",
	} {
		if !strings.Contains(inner, want) {
			t.Errorf("falta %s", want)
		}
	}
	if _, err := buildVerifactuConsulta("", "x", "2026-10-01", "", nil); err == nil {
		t.Error("se esperaba error sin NIF")
	}
}

func TestBuildVerifactuConsultaConClavePaginacion(t *testing.T) {
	inner, err := buildVerifactuConsulta("B19995869", "Empresa de Pruebas", "2026-10-01", "2026-0007",
		&verifactuIDFacturaBC{EmisorNIF: "B19995869", NumSerie: "2026-0006", Fecha: "2026-10-01"})
	if err != nil {
		t.Fatalf("consulta: %v", err)
	}
	clave := `<ClavePaginacion>` +
		`<sf:IDEmisorFactura>B19995869</sf:IDEmisorFactura>` +
		`<sf:NumSerieFactura>2026-0006</sf:NumSerieFactura>` +
		`<sf:FechaExpedicionFactura>01-10-2026</sf:FechaExpedicionFactura>` +
		`</ClavePaginacion>`
	if !strings.Contains(inner, clave) {
		t.Errorf("falta ClavePaginacion (fecha convertida a DD-MM-YYYY): %s", inner)
	}
	// Posición: último hijo de FiltroConsulta (XSD: después de todo, antes del cierre).
	if i, j := strings.Index(inner, clave), strings.Index(inner, "</FiltroConsulta>"); i < 0 || i > j {
		t.Errorf("ClavePaginacion debe ir justo antes de </FiltroConsulta> (i=%d j=%d)", i, j)
	}
	// Sin clave no debe aparecer.
	plain, _ := buildVerifactuConsulta("B19995869", "E", "2026-10-01", "", nil)
	if strings.Contains(plain, "ClavePaginacion") {
		t.Error("sin clave no debe emitirse ClavePaginacion")
	}
	// Validación: clave incompleta / fecha mala.
	if _, err := buildVerifactuConsulta("B19995869", "E", "2026-10-01", "",
		&verifactuIDFacturaBC{NumSerie: ""}); err == nil {
		t.Error("se esperaba error con clave incompleta")
	}
	if _, err := buildVerifactuConsulta("B19995869", "E", "2026-10-01", "",
		&verifactuIDFacturaBC{NumSerie: "X", Fecha: "01-10-2026"}); err == nil {
		t.Error("se esperaba error con fecha no ISO en la clave")
	}
}

func TestParseConsultaResponsePaginacion(t *testing.T) {
	r, err := parseConsultaResponse([]byte(fixtureConsultaPagina))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if r.IndicadorPaginacion != "S" {
		t.Errorf("IndicadorPaginacion = %q, se esperaba S", r.IndicadorPaginacion)
	}
	if r.ClavePaginacion == nil || r.ClavePaginacion.NumSerie != "2026-0007" || r.ClavePaginacion.Fecha != "01-10-2026" {
		t.Errorf("ClavePaginacion = %+v", r.ClavePaginacion)
	}
	if len(r.Registros) != 1 {
		t.Errorf("registros = %d", len(r.Registros))
	}
	// La respuesta sin paginación (fixture base) no tiene clave.
	r2, err := parseConsultaResponse([]byte(fixtureConsulta))
	if err != nil {
		t.Fatalf("parse base: %v", err)
	}
	if r2.ClavePaginacion != nil {
		t.Error("sin elemento, la clave debe ser nil")
	}
}

// --- Endpoint por entorno ---

func TestVerifactuEndpointSelection(t *testing.T) {
	t.Setenv("VERIFACTU_ENDPOINT", "")
	t.Setenv("VERIFACTU_ENV", "sandbox")
	t.Setenv("VERIFACTU_SELLO", "0")
	if got := verifactuEndpoint(); !strings.Contains(got, "prewww1.aeat.es") {
		t.Errorf("sandbox = %q", got)
	}
	t.Setenv("VERIFACTU_SELLO", "1")
	if got := verifactuEndpoint(); !strings.Contains(got, "prewww10.aeat.es") {
		t.Errorf("sello sandbox = %q", got)
	}
	t.Setenv("VERIFACTU_ENV", "production")
	if got := verifactuEndpoint(); !strings.Contains(got, "www10.agenciatributaria.gob.es") {
		t.Errorf("sello producción = %q", got)
	}
	t.Setenv("VERIFACTU_SELLO", "0")
	if got := verifactuEndpoint(); !strings.Contains(got, "www1.agenciatributaria.gob.es") {
		t.Errorf("producción = %q", got)
	}
	t.Setenv("VERIFACTU_ENDPOINT", "https://custom.example/soap")
	if got := verifactuEndpoint(); got != "https://custom.example/soap" {
		t.Errorf("override = %q", got)
	}
}

// --- Parseo de respuestas ---

const fixtureRespuestaCorrecta = `<?xml version="1.0" encoding="UTF-8"?>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
 <soapenv:Body>
  <RespuestaRegFactuSistemaFacturacion xmlns="https://www2.agenciatributaria.gob.es/static_files/common/internet/dep/aplicaciones/es/aeat/tike/cont/ws/RespuestaSuministro.xsd">
   <Cabecera><ObligadoEmision><NombreRazonSocial>X</NombreRazonSocial><NIF>B19995869</NIF></ObligadoEmision></Cabecera>
   <CSV>CSV-ABC123</CSV>
   <DatosPresentacion><NIFPresentador>B19995869</NIFPresentador><TimestampPresentacion>2026-10-01T12:00:00</TimestampPresentacion></DatosPresentacion>
   <EstadoEnvio>Correcto</EstadoEnvio>
   <RespuestaLinea>
    <IDFactura><IDEmisorFactura>B19995869</IDEmisorFactura><NumSerieFactura>2026-0007</NumSerieFactura><FechaExpedicionFactura>01-10-2026</FechaExpedicionFactura></IDFactura>
    <Operacion><TipoOperacion>Alta</TipoOperacion><Subsanacion>N</Subsanacion><RechazoPrevio>N</RechazoPrevio></Operacion>
    <EstadoRegistro>Correcto</EstadoRegistro>
   </RespuestaLinea>
  </RespuestaRegFactuSistemaFacturacion>
 </soapenv:Body>
</soapenv:Envelope>`

const fixtureRespuestaDeferred = `<?xml version="1.0" encoding="UTF-8"?>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
 <soapenv:Body>
  <RespuestaRegFactuSistemaFacturacion xmlns="x">
   <Cabecera/>
   <TiempoEsperaEnvio>120</TiempoEsperaEnvio>
   <EstadoEnvio>Correcto</EstadoEnvio>
  </RespuestaRegFactuSistemaFacturacion>
 </soapenv:Body>
</soapenv:Envelope>`

const fixtureSoapFault = `<?xml version="1.0" encoding="UTF-8"?>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
 <soapenv:Body>
  <soapenv:Fault><faultcode>soapenv:Server</faultcode><faultstring>boom</faultstring></soapenv:Fault>
 </soapenv:Body>
</soapenv:Envelope>`

const fixtureConsulta = `<?xml version="1.0" encoding="UTF-8"?>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
 <soapenv:Body>
  <RespuestaConsultaFactuSistemaFacturacion xmlns="x">
   <ResultadoConsulta>Conforme</ResultadoConsulta>
   <RegistroRespuestaConsultaFactuSistemaFacturacion>
    <IDFactura><IDEmisorFactura>B19995869</IDEmisorFactura><NumSerieFactura>2026-0007</NumSerieFactura><FechaExpedicionFactura>01-10-2026</FechaExpedicionFactura></IDFactura>
    <EstadoRegistro><TimestampUltimaModificacion>2026-10-01T12:00:02</TimestampUltimaModificacion><EstadoRegistro>Correcto</EstadoRegistro></EstadoRegistro>
   </RegistroRespuestaConsultaFactuSistemaFacturacion>
  </RespuestaConsultaFactuSistemaFacturacion>
 </soapenv:Body>
</soapenv:Envelope>`

// Respuesta con más páginas: IndicadorPaginacion=S + ClavePaginacion.
const fixtureConsultaPagina = `<?xml version="1.0" encoding="UTF-8"?>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
 <soapenv:Body>
  <RespuestaConsultaFactuSistemaFacturacion xmlns="x">
   <ResultadoConsulta>Conforme</ResultadoConsulta>
   <IndicadorPaginacion>S</IndicadorPaginacion>
   <RegistroRespuestaConsultaFactuSistemaFacturacion>
    <IDFactura><IDEmisorFactura>B19995869</IDEmisorFactura><NumSerieFactura>2026-0007</NumSerieFactura><FechaExpedicionFactura>01-10-2026</FechaExpedicionFactura></IDFactura>
    <EstadoRegistro><TimestampUltimaModificacion>2026-10-01T12:00:02</TimestampUltimaModificacion><EstadoRegistro>Correcto</EstadoRegistro></EstadoRegistro>
   </RegistroRespuestaConsultaFactuSistemaFacturacion>
   <ClavePaginacion>
    <IDEmisorFactura>B19995869</IDEmisorFactura>
    <NumSerieFactura>2026-0007</NumSerieFactura>
    <FechaExpedicionFactura>01-10-2026</FechaExpedicionFactura>
   </ClavePaginacion>
  </RespuestaConsultaFactuSistemaFacturacion>
 </soapenv:Body>
</soapenv:Envelope>`

func TestParseAltaResponse(t *testing.T) {
	r, err := parseAltaResponse([]byte(fixtureRespuestaCorrecta))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if r.EstadoEnvio != "Correcto" || r.CSV != "CSV-ABC123" {
		t.Errorf("estado=%q csv=%q", r.EstadoEnvio, r.CSV)
	}
	if len(r.RespuestaLinea) != 1 {
		t.Fatalf("lineas = %d", len(r.RespuestaLinea))
	}
	ln := r.RespuestaLinea[0]
	if ln.EstadoRegistro != "Correcto" || ln.NumSerieFactura != "2026-0007" {
		t.Errorf("linea = %+v", ln)
	}
	if ln.Operacion.TipoOperacion != "Alta" {
		t.Errorf("operacion = %+v", ln.Operacion)
	}
	if r.DatosPresentacion.NIFPresentador != "B19995869" {
		t.Errorf("presentacion = %+v", r.DatosPresentacion)
	}
}

func TestParseAltaResponseDeferred(t *testing.T) {
	r, err := parseAltaResponse([]byte(fixtureRespuestaDeferred))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if r.TiempoEsperaEnvio != "120" {
		t.Errorf("TiempoEsperaEnvio = %q", r.TiempoEsperaEnvio)
	}
}

func TestParseAltaResponseFault(t *testing.T) {
	if _, err := parseAltaResponse([]byte(fixtureSoapFault)); err == nil || !strings.Contains(err.Error(), "boom") {
		t.Errorf("se esperaba SOAP Fault, got %v", err)
	}
}

func TestParseConsultaResponse(t *testing.T) {
	r, err := parseConsultaResponse([]byte(fixtureConsulta))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if r.ResultadoConsulta != "Conforme" {
		t.Errorf("resultado = %q", r.ResultadoConsulta)
	}
	if len(r.Registros) != 1 || r.Registros[0].EstadoRegistro.Estado != "Correcto" {
		t.Errorf("registros = %+v", r.Registros)
	}
}

// --- Utilidades de certificados para pruebas mTLS ---

type testCA struct {
	cert *x509.Certificate
	key  *rsa.PrivateKey
	pem  []byte
}

func newTestCA(t *testing.T) *testCA {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("clave CA: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "VeriFactu Test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("cert CA: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse CA: %v", err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	return &testCA{cert: cert, key: key, pem: pemBytes}
}

func (ca *testCA) leaf(t *testing.T, cn string, server bool) (*x509.Certificate, *rsa.PrivateKey) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("clave leaf: %v", err)
	}
	serial, err := rand.Int(rand.Reader, big.NewInt(1<<62))
	if err != nil {
		t.Fatalf("serial: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: cn, Organization: []string{"VeriFactu Test"}},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
		DNSNames:     []string{"localhost"},
	}
	if server {
		tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	} else {
		tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatalf("cert leaf: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse leaf: %v", err)
	}
	return cert, key
}

// --- Handler end-to-end contra un servidor AEAT simulado con mTLS ---

func TestVerifactuAltaHandlerMTLS(t *testing.T) {
	ca := newTestCA(t)

	// Servidor simulado: exige y verifica certificado de cliente.
	serverCert, serverKey := ca.leaf(t, "localhost", true)
	pool := x509.NewCertPool()
	pool.AddCert(ca.cert)

	var gotBody, gotContentType, gotSOAPAction string
	var gotVerifiedChains int
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotContentType = r.Header.Get("Content-Type")
		gotSOAPAction = r.Header.Get("SOAPAction")
		if r.TLS != nil {
			gotVerifiedChains = len(r.TLS.VerifiedChains)
		}
		body, _ := io.ReadAll(r.Body)
		gotBody = string(body)
		w.Header().Set("Content-Type", "text/xml; charset=utf-8")
		fmt.Fprint(w, fixtureRespuestaCorrecta)
	}))
	srv.TLS = &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{serverCert.Raw}, PrivateKey: serverKey, Leaf: serverCert}},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    pool,
	}
	srv.StartTLS()
	defer srv.Close()

	// Certificado de cliente en PKCS#12 + blob WPFE1 con clave del signer.
	caCert, caKey := ca.leaf(t, "cliente@prueba", false)
	material, err := mkKeyBundlePEM(t, caKey, caCert, ca.cert)
	if err != nil {
		t.Fatalf("bundle: %v", err)
	}
	wpfeKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("clave wpfe: %v", err)
	}
	oldConfig := activeConfig
	activeConfig = &signerConfig{privateKey: wpfeKey}
	t.Cleanup(func() { activeConfig = oldConfig })

	blob := encryptWPFE1(t, material, &wpfeKey.PublicKey)

	// El cliente confía en la CA del servidor vía VERIFACTU_EXTRA_CA.
	caPath := t.TempDir() + "/ca.pem"
	if err := os.WriteFile(caPath, ca.pem, 0o600); err != nil {
		t.Fatalf("escribir CA: %v", err)
	}
	t.Setenv("VERIFACTU_EXTRA_CA", caPath)
	t.Setenv("VERIFACTU_ENDPOINT", srv.URL)

	srv2 := httptest.NewServer(newMux())
	defer srv2.Close()

	payload, _ := json.Marshal(verifactuAltaRequest{
		Certificate: base64.StdEncoding.EncodeToString(blob),
		Record:      *sampleRecord(),
	})
	resp, err := http.Post(srv2.URL+"/verifactu/alta", "application/json", strings.NewReader(string(payload)))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}

	var result verifactuAltaResult
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		t.Fatalf("json: %v", err)
	}
	if result.EstadoEnvio != "Correcto" || result.CSV != "CSV-ABC123" {
		t.Errorf("resultado = %+v", result)
	}
	if len(result.Lineas) != 1 || result.Lineas[0].Estado != "Correcto" {
		t.Errorf("lineas = %+v", result.Lineas)
	}
	if len(result.Huella) != 64 {
		t.Errorf("huella = %q", result.Huella)
	}
	if result.Deferred {
		t.Error("no debe salir deferred")
	}

	// El servidor AEAT simulado vio mTLS y SOAP correctos.
	if gotVerifiedChains == 0 {
		t.Error("el servidor no recibió un certificado de cliente verificado (mTLS)")
	}
	if !strings.Contains(gotContentType, "text/xml") {
		t.Errorf("Content-Type = %q", gotContentType)
	}
	if gotSOAPAction != `""` {
		t.Errorf("SOAPAction = %q", gotSOAPAction)
	}
	if !strings.Contains(gotBody, "soapenv:Envelope") ||
		!strings.Contains(gotBody, "<RegistroAlta") ||
		!strings.Contains(gotBody, "<Huella>") {
		t.Errorf("el cuerpo SOAP no contiene el registro: %s", gotBody[:200])
	}
}

func TestVerifactuAltaHandlerErrors(t *testing.T) {
	oldConfig := activeConfig
	wpfeKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("clave: %v", err)
	}
	activeConfig = &signerConfig{privateKey: wpfeKey}
	t.Cleanup(func() { activeConfig = oldConfig })

	srv := httptest.NewServer(newMux())
	defer srv.Close()

	post := func(body string) int {
		t.Helper()
		resp, err := http.Post(srv.URL+"/verifactu/alta", "application/json", strings.NewReader(body))
		if err != nil {
			t.Fatalf("POST: %v", err)
		}
		defer resp.Body.Close()
		return resp.StatusCode
	}

	// Sin certificate.
	if code := post(`{"record":{}}`); code != http.StatusBadRequest {
		t.Errorf("sin certificado: %d", code)
	}
	// Certificado no base64.
	if code := post(`{"certificate":"!!","record":{}}`); code != http.StatusBadRequest {
		t.Errorf("b64: %d", code)
	}
	// Registro inválido (inputErrf) -> 400.
	blob := encryptWPFE1(t, []byte("no-bundle"), &wpfeKey.PublicKey)
	payload, _ := json.Marshal(verifactuAltaRequest{
		Certificate: base64.StdEncoding.EncodeToString(blob),
		Record:      verifactuRecord{Kind: "otra"},
	})
	if code := post(string(payload)); code != http.StatusBadRequest {
		t.Errorf("bundle inválido: %d", code)
	}
}

func TestVerifactuConsultaHandler(t *testing.T) {
	ca := newTestCA(t)
	serverCert, serverKey := ca.leaf(t, "localhost", true)
	pool := x509.NewCertPool()
	pool.AddCert(ca.cert)

	var gotConsultaBody string
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		gotConsultaBody = string(b)
		w.Header().Set("Content-Type", "text/xml; charset=utf-8")
		fmt.Fprint(w, fixtureConsultaPagina)
	}))
	srv.TLS = &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{serverCert.Raw}, PrivateKey: serverKey, Leaf: serverCert}},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    pool,
	}
	srv.StartTLS()
	defer srv.Close()

	caCert, caKey := ca.leaf(t, "cliente@prueba", false)
	material, err := mkKeyBundlePEM(t, caKey, caCert, ca.cert)
	if err != nil {
		t.Fatalf("bundle: %v", err)
	}
	wpfeKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("clave wpfe: %v", err)
	}
	oldConfig := activeConfig
	activeConfig = &signerConfig{privateKey: wpfeKey}
	t.Cleanup(func() { activeConfig = oldConfig })
	blob := encryptWPFE1(t, material, &wpfeKey.PublicKey)

	caPath := t.TempDir() + "/ca.pem"
	_ = os.WriteFile(caPath, ca.pem, 0o600)
	t.Setenv("VERIFACTU_EXTRA_CA", caPath)
	t.Setenv("VERIFACTU_ENDPOINT", srv.URL)

	web := httptest.NewServer(newMux())
	defer web.Close()

	payload, _ := json.Marshal(verifactuConsultaRequest{
		Certificate: base64.StdEncoding.EncodeToString(blob),
		NIF:         "B19995869",
		Nombre:      "Empresa de Pruebas",
		Fecha:       "2026-10-01",
		Numero:      "2026-0007",
		ClavePaginacion: &verifactuIDFacturaBC{
			EmisorNIF: "B19995869",
			NumSerie:  "2026-0006",
			Fecha:     "2026-10-01",
		},
	})
	resp, err := http.Post(web.URL+"/verifactu/consulta", "application/json", strings.NewReader(string(payload)))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	var result verifactuConsultaResult
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		t.Fatalf("json: %v", err)
	}
	if result.ResultadoConsulta != "Conforme" || len(result.Registros) != 1 {
		t.Errorf("resultado = %+v", result)
	}
	if result.Registros[0].Estado != "Correcto" {
		t.Errorf("registro = %+v", result.Registros[0])
	}
	if result.IndPagina != "S" {
		t.Errorf("ind_pagina = %q, se esperaba S", result.IndPagina)
	}
	if result.ClavePaginacion == nil || result.ClavePaginacion.NumSerie != "2026-0007" {
		t.Errorf("clave_paginacion = %+v", result.ClavePaginacion)
	}
	// El SOAP saliente lleva la clave pedida (fecha convertida DD-MM-YYYY).
	if !strings.Contains(gotConsultaBody, "<ClavePaginacion>") ||
		!strings.Contains(gotConsultaBody, "<sf:NumSerieFactura>2026-0006</sf:NumSerieFactura>") ||
		!strings.Contains(gotConsultaBody, "<sf:FechaExpedicionFactura>01-10-2026</sf:FechaExpedicionFactura>") {
		t.Errorf("el SOAP no lleva ClavePaginacion: %s", gotConsultaBody)
	}
}

// --- Detección de deferred vs veredicto final ---

const fixtureRespuestaSoloTasa = `<?xml version="1.0" encoding="UTF-8"?>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
 <soapenv:Body>
  <RespuestaRegFactuSistemaFacturacion xmlns="x">
   <Cabecera/>
   <TiempoEsperaEnvio>120</TiempoEsperaEnvio>
  </RespuestaRegFactuSistemaFacturacion>
 </soapenv:Body>
</soapenv:Envelope>`

const fixtureRespuestaIncorrectoConTasa = `<?xml version="1.0" encoding="UTF-8"?>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
 <soapenv:Body>
  <RespuestaRegFactuSistemaFacturacion xmlns="x">
   <Cabecera/>
   <TiempoEsperaEnvio>60</TiempoEsperaEnvio>
   <EstadoEnvio>Incorrecto</EstadoEnvio>
   <RespuestaLinea>
    <IDFactura><IDEmisorFactura>B19995869</IDEmisorFactura><NumSerieFactura>2026-0003</NumSerieFactura><FechaExpedicionFactura>30-09-2026</FechaExpedicionFactura></IDFactura>
    <EstadoRegistro>Incorrecto</EstadoRegistro>
    <CodigoErrorRegistro>1239</CodigoErrorRegistro>
    <DescripcionErrorRegistro>Error en el bloque Destinatario.</DescripcionErrorRegistro>
   </RespuestaLinea>
  </RespuestaRegFactuSistemaFacturacion>
 </soapenv:Body>
</soapenv:Envelope>`

func TestMapAltaResponsePureRateLimitIsDeferred(t *testing.T) {
	resp, err := parseAltaResponse([]byte(fixtureRespuestaSoloTasa))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	r := mapAltaResponse(resp, "H", "T", "ep", nil)
	if !r.Deferred || r.RetryAfterSeconds != 120 {
		t.Errorf("deferred=%v retry=%d, se esperaba deferred con 120", r.Deferred, r.RetryAfterSeconds)
	}
}

func TestMapAltaResponseVerdictWithRateLimitIsFinal(t *testing.T) {
	resp, err := parseAltaResponse([]byte(fixtureRespuestaIncorrectoConTasa))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	r := mapAltaResponse(resp, "H", "T", "ep", nil)
	if r.Deferred {
		t.Error("un EstadoEnvio+RespuestaLinea con TiempoEsperaEnvio NO es deferred (bug que enmascaraba Incorrecto como pendiente)")
	}
	if r.EstadoEnvio != "Incorrecto" {
		t.Errorf("estado_envio = %q", r.EstadoEnvio)
	}
	if len(r.Lineas) != 1 {
		t.Fatalf("lineas = %d", len(r.Lineas))
	}
	if r.Lineas[0].Estado != "Incorrecto" || r.Lineas[0].Codigo != "1239" {
		t.Errorf("linea = %+v", r.Lineas[0])
	}
}

// Regresión: la AEAT devuelve 302 a su página de errores (p. ej. erro4033,
// "sin certificado electrónico") cuando falla antes del SOAP. El cliente no
// debe seguir la redirección (HTML incomprensible como cuerpo) y el error
// debe mencionar el destino para poder diagnosticar.
func TestPostVerifactuSOAPRejectsRedirect(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://sede.agenciatributaria.gob.es/Sede/errores/erro4033.html", http.StatusFound)
	}))
	defer srv.Close()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("clave: %v", err)
	}
	material, err := mkKeyBundlePEM(t, key, mkSelfSignedCert(t, key))
	if err != nil {
		t.Fatalf("bundle: %v", err)
	}
	bundle, err := parseKeyBundle(material)
	if err != nil {
		t.Fatalf("parseKeyBundle: %v", err)
	}
	client, err := newVerifactuClient(bundle, nil, 5*time.Second)
	if err != nil {
		t.Fatalf("newVerifactuClient: %v", err)
	}

	_, err = postVerifactuSOAP(client, srv.URL, "<x/>")
	if err == nil {
		t.Fatal("se esperaba error con la redirección")
	}
	if !strings.Contains(err.Error(), "HTTP 302") || !strings.Contains(err.Error(), "redirige a") {
		t.Errorf("mensaje sin diagnóstico de redirección: %v", err)
	}
	if strings.Contains(err.Error(), "<meta>") {
		t.Errorf("no debe parsear el HTML de la página de error: %v", err)
	}
}
