package main

import (
	"crypto/sha256"
	"encoding/hex"
	"math"
	"strconv"
	"strings"
	"time"
)

// Namespaces of los esquemas AEAT (targetNamespace de los XSD oficiales).
const (
	vfLRNS       = "https://www2.agenciatributaria.gob.es/static_files/common/internet/dep/aplicaciones/es/aeat/tike/cont/ws/SuministroLR.xsd"
	vfSFNS       = "https://www2.agenciatributaria.gob.es/static_files/common/internet/dep/aplicaciones/es/aeat/tike/cont/ws/SuministroInformacion.xsd"
	vfConsultaNS = "https://www2.agenciatributaria.gob.es/static_files/common/internet/dep/aplicaciones/es/aeat/tike/cont/ws/ConsultaLR.xsd"

	vfVersion    = "1.0"
	vfSoftwareID = "WP" // IdSistemaInformatico: TextMax2Type
)

// verifactuRecord es el modelo JSON que WP envía al signer para construir un
// registro de facturación (alta o anulación). Fechas en ISO YYYY-MM-DD; las
// cantidades como decimales con punto.
type verifactuRecord struct {
	Kind         string                `json:"kind"` // "alta" | "anulacion"
	EmisorNIF    string                `json:"emisor_nif"`
	EmisorNombre string                `json:"emisor_nombre"`
	Numero       string                `json:"numero"`
	Fecha        string                `json:"fecha"` // YYYY-MM-DD
	TipoFactura  string                `json:"tipo_factura,omitempty"`
	Descripcion  string                `json:"descripcion,omitempty"`
	Destinatario verifactuDestinatario `json:"destinatario,omitempty"`
	Detalles     []verifactuDetalle    `json:"detalles,omitempty"`
	CuotaTotal   string                `json:"cuota_total,omitempty"`
	ImporteTotal string                `json:"importe_total,omitempty"`
	Previous     *verifactuPrevious    `json:"previous,omitempty"`
	Software     *verifactuSoftware    `json:"software,omitempty"`
}

type verifactuDestinatario struct {
	Nombre string `json:"nombre,omitempty"`
	NIF    string `json:"nif,omitempty"`
	Pais   string `json:"pais,omitempty"` // ISO3; si ≠ ESP se usa IDOtro/IDType 07
}

type verifactuDetalle struct {
	Impuesto       string `json:"impuesto,omitempty"`      // default "01" (IVA)
	ClaveRegimen   string `json:"clave_regimen,omitempty"` // default "01"
	Calificacion   string `json:"calificacion,omitempty"`  // default "S1"
	TipoImpositivo string `json:"tipo_impositivo"`
	Base           string `json:"base"`
	Cuota          string `json:"cuota"`
}

type verifactuPrevious struct {
	Huella    string `json:"huella"`
	EmisorNIF string `json:"emisor_nif"`
	Numero    string `json:"num_serie"`
	FechaEs   string `json:"fecha_es"` // DD-MM-YYYY (formato AEAT, tal cual lo devuelve la respuesta)
}

type verifactuSoftware struct {
	NombreRazon       string `json:"nombre_razon,omitempty"`
	NIF               string `json:"nif,omitempty"`
	Nombre            string `json:"nombre,omitempty"`
	ID                string `json:"id,omitempty"`
	Version           string `json:"version,omitempty"`
	NumeroInstalacion string `json:"numero_instalacion,omitempty"`
}

// huellaAlta calcula el Huella de un RegistroAlta (SHA-256, hex mayúsculas).
// Orden exacto según la spec oficial de huella de AEAT (v0.1.2 §3.a); para el
// registro génesis prev es cadena vacía (el campo sigue presente).
func huellaAlta(emisor, serie, fechaES, tipo, cuota, importe, fechaHoraGen, prev string) string {
	raw := strings.Join([]string{
		"IDEmisorFactura=" + emisor,
		"NumSerieFactura=" + serie,
		"FechaExpedicionFactura=" + fechaES,
		"TipoFactura=" + tipo,
		"CuotaTotal=" + cuota,
		"ImporteTotal=" + importe,
		"Huella=" + prev,
		"FechaHoraHusoGenRegistro=" + fechaHoraGen,
	}, "&")
	sum := sha256.Sum256([]byte(raw))
	return strings.ToUpper(hex.EncodeToString(sum[:]))
}

// huellaAnulacion calcula el Huella de un RegistroAnulacion: conjunto de
// campos propio con nombres "*Anulada" (spec §3.b) — no reutilizar el del alta.
func huellaAnulacion(emisor, serie, fechaES, fechaHoraGen, prev string) string {
	raw := strings.Join([]string{
		"IDEmisorFacturaAnulada=" + emisor,
		"NumSerieFacturaAnulada=" + serie,
		"FechaExpedicionFacturaAnulada=" + fechaES,
		"Huella=" + prev,
		"FechaHoraHusoGenRegistro=" + fechaHoraGen,
	}, "&")
	sum := sha256.Sum256([]byte(raw))
	return strings.ToUpper(hex.EncodeToString(sum[:]))
}

// veriFecha convierte YYYY-MM-DD (Facturae) a DD-MM-YYYY (AEAT).
func veriFecha(iso string) (string, error) {
	if len(iso) != 10 || iso[4] != '-' || iso[7] != '-' {
		return "", inputErrf("fecha no válida (se esperaba YYYY-MM-DD): %q", iso)
	}
	return iso[8:10] + "-" + iso[5:7] + "-" + iso[0:4], nil
}

// veriImporte normaliza un decimal con punto a 2 cifras (HALF_UP).
func veriImporte(s string) (string, error) {
	f, err := strconv.ParseFloat(strings.TrimSpace(s), 64)
	if err != nil {
		return "", inputErrf("importe no válido: %q", s)
	}
	return strconv.FormatFloat(math.Round(f*100)/100, 'f', 2, 64), nil
}

// veriFechaHora genera FechaHoraHusoGenRegistro con offset horario (ISO 8601).
func veriFechaHora(now time.Time) string {
	return now.Format("2006-01-02T15:04:05-07:00")
}

func veriSoftware(r *verifactuRecord) verifactuSoftware {
	sw := verifactuSoftware{
		NombreRazon:       r.EmisorNombre,
		NIF:               r.EmisorNIF,
		Nombre:            "WPFacturaE",
		ID:                vfSoftwareID,
		Version:           "1.0",
		NumeroInstalacion: "001",
	}
	if r.Software != nil {
		if r.Software.NombreRazon != "" {
			sw.NombreRazon = r.Software.NombreRazon
		}
		if r.Software.NIF != "" {
			sw.NIF = r.Software.NIF
		}
		if r.Software.Nombre != "" {
			sw.Nombre = r.Software.Nombre
		}
		if r.Software.ID != "" {
			sw.ID = r.Software.ID
		}
		if r.Software.Version != "" {
			sw.Version = r.Software.Version
		}
		if r.Software.NumeroInstalacion != "" {
			sw.NumeroInstalacion = r.Software.NumeroInstalacion
		}
	}
	if len(sw.ID) > 2 {
		sw.ID = sw.ID[:2]
	}
	return sw
}

func veriEncadenamiento(prev *verifactuPrevious) string {
	if prev == nil || prev.Huella == "" {
		return `<Encadenamiento><PrimerRegistro>S</PrimerRegistro></Encadenamiento>`
	}
	return `<Encadenamiento><RegistroAnterior>` +
		`<IDEmisorFactura>` + escapeXMLText(prev.EmisorNIF) + `</IDEmisorFactura>` +
		`<NumSerieFactura>` + escapeXMLText(prev.Numero) + `</NumSerieFactura>` +
		`<FechaExpedicionFactura>` + escapeXMLText(prev.FechaEs) + `</FechaExpedicionFactura>` +
		`<Huella>` + escapeXMLText(prev.Huella) + `</Huella>` +
		`</RegistroAnterior></Encadenamiento>`
}

func veriSistemaInformatico(sw verifactuSoftware) string {
	return `<SistemaInformatico>` +
		`<NombreRazon>` + escapeXMLText(sw.NombreRazon) + `</NombreRazon>` +
		`<NIF>` + escapeXMLText(sw.NIF) + `</NIF>` +
		`<NombreSistemaInformatico>` + escapeXMLText(sw.Nombre) + `</NombreSistemaInformatico>` +
		`<IdSistemaInformatico>` + escapeXMLText(sw.ID) + `</IdSistemaInformatico>` +
		`<Version>` + escapeXMLText(sw.Version) + `</Version>` +
		`<NumeroInstalacion>` + escapeXMLText(sw.NumeroInstalacion) + `</NumeroInstalacion>` +
		`<TipoUsoPosibleSoloVerifactu>S</TipoUsoPosibleSoloVerifactu>` +
		`<TipoUsoPosibleMultiOT>N</TipoUsoPosibleMultiOT>` +
		`<IndicadorMultiplesOT>N</IndicadorMultiplesOT>` +
		`</SistemaInformatico>`
}

func veriDestinatarios(d verifactuDestinatario) string {
	if d.Nombre == "" && d.NIF == "" {
		return ""
	}
	var inner string
	if d.Pais != "" && !strings.EqualFold(d.Pais, "ESP") && !strings.EqualFold(d.Pais, "ES") {
		inner = `<IDOtro>` +
			`<CodigoPais>` + escapeXMLText(strings.ToUpper(d.Pais)) + `</CodigoPais>` +
			`<IDType>07</IDType>` +
			`<ID>` + escapeXMLText(d.NIF) + `</ID>` +
			`</IDOtro>`
	} else {
		inner = `<NIF>` + escapeXMLText(d.NIF) + `</NIF>`
	}
	return `<Destinatarios><IDDestinatario>` +
		`<NombreRazon>` + escapeXMLText(d.Nombre) + `</NombreRazon>` + inner +
		`</IDDestinatario></Destinatarios>`
}

func veriDesglose(detalles []verifactuDetalle) (string, error) {
	if len(detalles) == 0 {
		return "", inputErrf("falta el desglose de impuestos (detalles)")
	}
	if len(detalles) > 12 {
		return "", inputErrf("demasiadas líneas de desglose (máx. 12)")
	}
	var b strings.Builder
	b.WriteString(`<Desglose>`)
	for _, d := range detalles {
		impuesto := d.Impuesto
		if impuesto == "" {
			impuesto = "01"
		}
		clave := d.ClaveRegimen
		if clave == "" {
			clave = "01"
		}
		calif := d.Calificacion
		if calif == "" {
			calif = "S1"
		}
		base, err := veriImporte(d.Base)
		if err != nil {
			return "", err
		}
		cuota, err := veriImporte(d.Cuota)
		if err != nil {
			return "", err
		}
		tipo := d.TipoImpositivo
		if tipo != "" {
			if t, err := veriImporte(tipo); err == nil {
				tipo = t
			} else {
				return "", err
			}
		}
		b.WriteString(`<DetalleDesglose>`)
		b.WriteString(`<Impuesto>` + escapeXMLText(impuesto) + `</Impuesto>`)
		b.WriteString(`<ClaveRegimen>` + escapeXMLText(clave) + `</ClaveRegimen>`)
		b.WriteString(`<CalificacionOperacion>` + escapeXMLText(calif) + `</CalificacionOperacion>`)
		if tipo != "" {
			b.WriteString(`<TipoImpositivo>` + tipo + `</TipoImpositivo>`)
		}
		b.WriteString(`<BaseImponibleOimporteNoSujeto>` + base + `</BaseImponibleOimporteNoSujeto>`)
		b.WriteString(`<CuotaRepercutida>` + cuota + `</CuotaRepercutida>`)
		b.WriteString(`</DetalleDesglose>`)
	}
	b.WriteString(`</Desglose>`)
	return b.String(), nil
}

// buildVerifactuInner construye el elemento RegFactuSistemaFacturacion
// (envoltorio + RegistroAlta o RegistroAnulacion) listo para envolver en SOAP.
// Devuelve además el Huella generado y el FechaHoraHusoGenRegistro usado.
func buildVerifactuInner(r *verifactuRecord, now time.Time) (string, string, string, error) {
	if r.Kind != "alta" && r.Kind != "anulacion" {
		return "", "", "", inputErrf("kind debe ser \"alta\" o \"anulacion\"")
	}
	if r.EmisorNIF == "" || r.EmisorNombre == "" || r.Numero == "" {
		return "", "", "", inputErrf("emisor_nif, emisor_nombre y numero son obligatorios")
	}
	fechaES, err := veriFecha(r.Fecha)
	if err != nil {
		return "", "", "", err
	}
	fechaHoraGen := veriFechaHora(now)
	prevXML := veriEncadenamiento(r.Previous)
	prevH := ""
	if r.Previous != nil {
		prevH = r.Previous.Huella
	}
	sw := veriSoftware(r)

	var inner, huella string

	switch r.Kind {
	case "alta":
		if r.Destinatario.Nombre == "" || r.Destinatario.NIF == "" {
			return "", "", "", inputErrf("destinatario_nombre y destinatario_nif son obligatorios en un alta")
		}
		cuota, err := veriImporte(or0(r.CuotaTotal))
		if err != nil {
			return "", "", "", err
		}
		importe, err := veriImporte(or0(r.ImporteTotal))
		if err != nil {
			return "", "", "", err
		}
		tipo := r.TipoFactura
		if tipo == "" {
			tipo = "F1"
		}
		desglose, err := veriDesglose(r.Detalles)
		if err != nil {
			return "", "", "", err
		}
		desc := r.Descripcion
		if desc == "" {
			desc = "Prestación de servicios / entrega de bienes"
		}
		if len(desc) > 500 {
			desc = desc[:500]
		}

		huella = huellaAlta(r.EmisorNIF, r.Numero, fechaES, tipo, cuota, importe, fechaHoraGen, prevH)

		// xmlns en el propio <RegistroAlta>: el contenido va en el namespace
		// SuministroInformacion, no en el SuministroLR heredado de la raíz.
		inner = `<RegistroAlta xmlns="` + vfSFNS + `">` +
			`<IDVersion>` + vfVersion + `</IDVersion>` +
			`<IDFactura>` +
			`<IDEmisorFactura>` + escapeXMLText(r.EmisorNIF) + `</IDEmisorFactura>` +
			`<NumSerieFactura>` + escapeXMLText(r.Numero) + `</NumSerieFactura>` +
			`<FechaExpedicionFactura>` + fechaES + `</FechaExpedicionFactura>` +
			`</IDFactura>` +
			`<NombreRazonEmisor>` + escapeXMLText(r.EmisorNombre) + `</NombreRazonEmisor>` +
			`<Subsanacion>N</Subsanacion>` +
			`<RechazoPrevio>N</RechazoPrevio>` +
			`<TipoFactura>` + escapeXMLText(tipo) + `</TipoFactura>` +
			`<DescripcionOperacion>` + escapeXMLText(desc) + `</DescripcionOperacion>` +
			veriDestinatarios(r.Destinatario) +
			`<Cupon>N</Cupon>` +
			desglose +
			`<CuotaTotal>` + cuota + `</CuotaTotal>` +
			`<ImporteTotal>` + importe + `</ImporteTotal>` +
			prevXML +
			veriSistemaInformatico(sw) +
			`<FechaHoraHusoGenRegistro>` + fechaHoraGen + `</FechaHoraHusoGenRegistro>` +
			`<TipoHuella>01</TipoHuella>` +
			`<Huella>` + huella + `</Huella>` +
			`</RegistroAlta>`

	case "anulacion":
		huella = huellaAnulacion(r.EmisorNIF, r.Numero, fechaES, fechaHoraGen, prevH)

		inner = `<RegistroAnulacion xmlns="` + vfSFNS + `">` +
			`<IDVersion>` + vfVersion + `</IDVersion>` +
			`<IDFactura>` +
			`<IDEmisorFacturaAnulada>` + escapeXMLText(r.EmisorNIF) + `</IDEmisorFacturaAnulada>` +
			`<NumSerieFacturaAnulada>` + escapeXMLText(r.Numero) + `</NumSerieFacturaAnulada>` +
			`<FechaExpedicionFacturaAnulada>` + fechaES + `</FechaExpedicionFacturaAnulada>` +
			`</IDFactura>` +
			prevXML +
			veriSistemaInformatico(sw) +
			`<FechaHoraHusoGenRegistro>` + fechaHoraGen + `</FechaHoraHusoGenRegistro>` +
			`<TipoHuella>01</TipoHuella>` +
			`<Huella>` + huella + `</Huella>` +
			`</RegistroAnulacion>`
	}

	envelope := `<RegFactuSistemaFacturacion xmlns="` + vfLRNS + `" xmlns:sf="` + vfSFNS + `">` +
		// Cabecera es un elemento local de SuministroLR (elementFormDefault=
		// "qualified"): SIN prefijo hereda el xmlns por defecto (LR). Sus
		// hijos (CabeceraType, declarado en SuministroInformacion) sí van sf:.
		`<Cabecera>` +
		`<sf:ObligadoEmision>` +
		`<sf:NombreRazon>` + escapeXMLText(r.EmisorNombre) + `</sf:NombreRazon>` +
		`<sf:NIF>` + escapeXMLText(r.EmisorNIF) + `</sf:NIF>` +
		`</sf:ObligadoEmision>` +
		`</Cabecera>` +
		`<RegistroFactura>` + inner + `</RegistroFactura>` +
		`</RegFactuSistemaFacturacion>`

	return envelope, huella, fechaHoraGen, nil
}

// buildVerifactuConsulta construye ConsultaFactuSistemaFacturacion (ConsultaLR).
// La fecha (YYYY-MM-DD) determina el PeriodoImputacion; número opcional filtra.
func buildVerifactuConsulta(nif, nombre, fechaISO, numero string) (string, error) {
	if nif == "" || nombre == "" || fechaISO == "" {
		return "", inputErrf("nif, nombre y fecha son obligatorios para la consulta")
	}
	if len(fechaISO) != 10 || fechaISO[4] != '-' {
		return "", inputErrf("fecha no válida (se esperaba YYYY-MM-DD): %q", fechaISO)
	}
	ejercicio := fechaISO[0:4]
	periodo := fechaISO[5:7]

	var filtro strings.Builder
	filtro.WriteString(`<FiltroConsulta>` +
		`<PeriodoImputacion>` +
		`<sf:Ejercicio>` + ejercicio + `</sf:Ejercicio>` +
		`<sf:Periodo>` + periodo + `</sf:Periodo>` +
		`</PeriodoImputacion>`)
	if numero != "" {
		filtro.WriteString(`<NumSerieFactura>` + escapeXMLText(numero) + `</NumSerieFactura>`)
	}
	filtro.WriteString(`</FiltroConsulta>`)

	return `<ConsultaFactuSistemaFacturacion xmlns="` + vfConsultaNS + `" xmlns:sf="` + vfSFNS + `">` +
		`<Cabecera>` +
		`<sf:IDVersion>` + vfVersion + `</sf:IDVersion>` +
		`<sf:ObligadoEmision>` +
		`<sf:NombreRazon>` + escapeXMLText(nombre) + `</sf:NombreRazon>` +
		`<sf:NIF>` + escapeXMLText(nif) + `</sf:NIF>` +
		`</sf:ObligadoEmision>` +
		`</Cabecera>` +
		filtro.String() +
		`</ConsultaFactuSistemaFacturacion>`, nil
}

func or0(s string) string {
	if strings.TrimSpace(s) == "" {
		return "0.00"
	}
	return s
}
