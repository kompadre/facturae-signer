package main

import (
	"bytes"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/beevik/etree"
	"github.com/go-pdf/fpdf"
	qrcode "github.com/skip2/go-qrcode"
)

// URL base del cotejo QR para sistemas VERI*FACTU (spec §5.1). El entorno de
// pruebas es https://prewww2.aeat.es/wlpl/TIKE-CONT/ValidarQR y puede
// sobreescribirse con VERIFACTU_QR_BASE.
const defaultQRBase = "https://www2.agenciatributaria.gob.es/wlpl/TIKE-CONT/ValidarQR"

const (
	qrLabel   = "QR tributario:"
	qrLegend  = "Factura verificable en la sede electrónica de la AEAT"
	qrSizeMM  = 35.0 // spec §21.1: entre 30x30 y 40x40 mm
	qrQuietMM = 4.0  // spec: mínimo 2 mm de espacio en blanco (6 recomendados)
)

// invoicePDF es el modelo de datos extraído del XML Facturae para elrendición.
type invoicePDF struct {
	Number       string
	Issue        string // fecha original YYYY-MM-DD
	InvoiceClass string
	Currency     string

	Seller  partyPDF
	Buyer   partyPDF
	Centres []centrePDF

	Lines  []linePDF
	Taxes  []taxPDF // IVA agregado (TaxesOutputs)
	Totals totalsPDF

	Payment paymentPDF
}

type partyPDF struct {
	NIF, Name string
	Address   string
	PostCode  string
	Town      string
	Province  string
}

type centrePDF struct {
	Code string
	Role string // "01" | "02" | "03"
	Name string
	Desc string
}

type linePDF struct {
	Desc      string
	Quantity  string
	UnitPrice string
	TotalCost string
	Gross     string
	TaxRate   string
}

type taxPDF struct {
	Rate   string
	Base   string
	Amount string
}

type totalsPDF struct {
	Gross     string
	TaxOutput string
	Withheld  string
	Total     string
}

type paymentPDF struct {
	DueDate string
	Amount  string
	Means   string
	IBAN    string
}

func qrBaseURL() string {
	if v := os.Getenv("VERIFACTU_QR_BASE"); v != "" {
		return v
	}
	return defaultQRBase
}

// javaURLEncode codifica como java.net.URLEncoder.encode(value, "UTF-8")
// (spec §4.1): los no reservados A-Za-z0-9 y ". - _ *" quedan literales,
// el espacio se convierte en "+" y el resto en %XX mayúsculas.
func javaURLEncode(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
			c == '.' || c == '-' || c == '*' || c == '_':
			b.WriteByte(c)
		case c == ' ':
			b.WriteByte('+')
		default:
			fmt.Fprintf(&b, "%%%02X", c)
		}
	}
	return b.String()
}

// buildQRURL arma la URL del cotejo con exactamente los 4 parámetros
// obligatorios (spec §6): nif, numserie, fecha (DD-MM-AAAA) e importe.
func buildQRURL(base, nif, numserie, fecha, importe string) string {
	return base +
		"?nif=" + javaURLEncode(nif) +
		"&numserie=" + javaURLEncode(numserie) +
		"&fecha=" + javaURLEncode(fecha) +
		"&importe=" + javaURLEncode(importe)
}

func feText(root *etree.Element, path string) string {
	if el := root.FindElement(path); el != nil {
		return strings.TrimSpace(el.Text())
	}
	return ""
}

func partyFrom(el *etree.Element) partyPDF {
	if el == nil {
		return partyPDF{}
	}
	p := partyPDF{
		NIF: feText(el, "TaxIdentification/TaxIdentificationNumber"),
	}
	if corp := feText(el, "LegalEntity/CorporateName"); corp != "" {
		p.Name = corp
	} else {
		p.Name = strings.TrimSpace(strings.Join([]string{
			feText(el, "Individual/Name"),
			feText(el, "Individual/FirstSurname"),
			feText(el, "Individual/SecondSurname"),
		}, " "))
	}
	addr := el.FindElement("LegalEntity/AddressInSpain")
	if addr == nil {
		addr = el.FindElement("Individual/AddressInSpain")
	}
	if addr == nil {
		addr = el.FindElement("AddressInSpain")
	}
	if addr != nil {
		p.Address = feText(addr, "Address")
		p.PostCode = feText(addr, "PostCode")
		p.Town = feText(addr, "Town")
		p.Province = feText(addr, "Province")
	}
	return p
}

// parseInvoicePDFModel extrae los datos de la factura del XML Facturae.
// Un XML bien formado pero sin factura dentro es error de entrada (400).
func parseInvoicePDFModel(xmlBytes []byte) (*invoicePDF, error) {
	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(xmlBytes); err != nil {
		return nil, inputErrf("xml no bien formado: %v", err)
	}
	root := doc.Root()
	if root == nil || root.Tag != "Facturae" {
		return nil, inputErrf("el documento no es una factura Facturae")
	}

	m := &invoicePDF{
		Number:       feText(root, "Invoices/Invoice/InvoiceHeader/InvoiceNumber"),
		Issue:        feText(root, "Invoices/Invoice/InvoiceIssueData/IssueDate"),
		InvoiceClass: feText(root, "Invoices/Invoice/InvoiceHeader/InvoiceClass"),
		Currency:     feText(root, "Invoices/Invoice/InvoiceIssueData/InvoiceCurrencyCode"),
		Seller:       partyFrom(root.FindElement("Parties/SellerParty")),
		Buyer:        partyFrom(root.FindElement("Parties/BuyerParty")),
	}

	for _, c := range root.FindElements("Parties/BuyerParty/AdministrativeCentres/AdministrativeCentre") {
		m.Centres = append(m.Centres, centrePDF{
			Code: feText(c, "CentreCode"),
			Role: feText(c, "RoleTypeCode"),
			Name: feText(c, "Name"),
			Desc: feText(c, "CentreDescription"),
		})
	}

	for _, l := range root.FindElements("Invoices/Invoice/Items/InvoiceLine") {
		m.Lines = append(m.Lines, linePDF{
			Desc:      feText(l, "ItemDescription"),
			Quantity:  feText(l, "Quantity"),
			UnitPrice: feText(l, "UnitPriceWithoutTax"),
			TotalCost: feText(l, "TotalCost"),
			Gross:     feText(l, "GrossAmount"),
			TaxRate:   feText(l, "TaxesOutputs/Tax/TaxRate"),
		})
	}

	for _, t := range root.FindElements("Invoices/Invoice/TaxesOutputs/Tax") {
		m.Taxes = append(m.Taxes, taxPDF{
			Rate:   feText(t, "TaxRate"),
			Base:   feText(t, "TaxableBase/TotalAmount"),
			Amount: feText(t, "TaxAmount/TotalAmount"),
		})
	}

	m.Totals = totalsPDF{
		Gross:     feText(root, "Invoices/Invoice/InvoiceTotals/TotalGrossAmount"),
		TaxOutput: feText(root, "Invoices/Invoice/InvoiceTotals/TotalTaxOutputs"),
		Withheld:  feText(root, "Invoices/Invoice/InvoiceTotals/TotalTaxesWithheld"),
		Total:     feText(root, "Invoices/Invoice/InvoiceTotals/InvoiceTotal"),
	}

	if inst := root.FindElement("Invoices/Invoice/PaymentDetails/Installment"); inst != nil {
		m.Payment = paymentPDF{
			DueDate: feText(inst, "InstallmentDueDate"),
			Amount:  feText(inst, "InstallmentAmount"),
			Means:   feText(inst, "PaymentMeans"),
			IBAN:    feText(inst, "AccountToBeCredited/IBAN"),
		}
	}

	return m, nil
}

// fechasDDMMAAAA convierte YYYY-MM-DD (Facturae) a DD-MM-AAAA (spec §6).
func fechasDDMMAAAA(iso string) string {
	t, err := time.Parse("2006-01-02", iso)
	if err != nil {
		return iso
	}
	return t.Format("02-01-2006")
}

// esNum muestra un decimal con coma (estilo español): "12.10" → "12,10".
func esNum(s string) string {
	return strings.Replace(s, ".", ",", 1)
}

var centreRoleLabels = map[string]string{
	"01": "Oficina Contable",
	"02": "Órgano Gestor",
	"03": "Unidad Tramitadora",
}

var paymentMeansLabels = map[string]string{
	"01": "Efectivo",
	"02": "Domiciliación bancaria",
	"04": "Transferencia",
	"05": "Giro postal",
	"06": "Letra de cambio",
	"07": "Pagaré a la orden",
	"09": "Pago por compensación",
	"12": "Documentary credit",
	"19": "Tarjeta de crédito",
}

func paymentMeansLabel(code string) string {
	if l, ok := paymentMeansLabels[code]; ok {
		return l
	}
	return "Medio de pago " + code
}

// utf8ToWinAnsi convierte texto UTF-8 al juego de caracteres WinAnsi (CP1252)
// que usan las fuentes núcleo de PDF. Los acentos españoles están en Latin-1;
// el resto de CP1252 (€, comillas, …) se mapea explícitamente y lo no
// representable se sustituye por "?". Sin esta conversión, fpdf escribe los
// bytes UTF-8 tal cual y los visores muestran "Ã³" en lugar de "ó".
func utf8ToWinAnsi(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		switch {
		case r < 0x80:
			b.WriteByte(byte(r))
		case r >= 0xA0 && r <= 0xFF:
			b.WriteByte(byte(r)) // Latin-1: acentos, Ñ, «», ·
		default:
			if v, ok := cp1252Extras[r]; ok {
				b.WriteByte(v)
			} else {
				b.WriteByte('?')
			}
		}
	}
	return b.String()
}

var cp1252Extras = map[rune]byte{
	'€': 0x80, '‚': 0x82, '„': 0x84, '…': 0x85, '†': 0x86, '‡': 0x87,
	'‰': 0x89, 'Š': 0x8A, '‹': 0x8B, 'Œ': 0x8C, 'Ž': 0x8E,
	'‘': 0x91, '’': 0x92, '“': 0x93, '”': 0x94, '•': 0x95, '–': 0x96,
	'—': 0x97, '™': 0x99, 'š': 0x9A, '›': 0x9B, 'œ': 0x9C, 'ž': 0x9E,
	'Ÿ': 0x9F,
}

// pdfSafe deja solo runes con ancho en la tabla de fuentes núcleo (< 256,
// es decir ASCII + Latin-1/CP1252); lo demás se sustituye por "?". Evita el
// panic de fpdf.SplitText al indexar su tabla de anchos con un rune grande.
func pdfSafe(s string) string {
	hasWide := false
	for _, r := range s {
		if r >= 256 {
			hasWide = true
			break
		}
	}
	if !hasWide {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		if r >= 256 {
			b.WriteByte('?')
		} else {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// renderInvoicePDF genera el PDF A4 de la factura con el bloque QR
// tributario (spec §3: al principio de la factura, centrado, con el texto
// "QR tributario:" encima y la leyenda VERI*FACTU debajo).
func renderInvoicePDF(m *invoicePDF) ([]byte, error) {
	png, err := qrcode.Encode(
		buildQRURL(qrBaseURL(), m.Seller.NIF, m.Number, fechasDDMMAAAA(m.Issue), m.Totals.Total),
		qrcode.Medium,
		600, // resolución de impresión holgada (~434 dpi a 35 mm)
	)
	if err != nil {
		return nil, fmt.Errorf("generar QR: %w", err)
	}

	p := fpdf.New("P", "mm", "A4", "")
	p.SetAutoPageBreak(true, 20)
	p.SetMargins(15, 10, 15)
	p.AliasNbPages("{nb}") // sustituye {nb} por el total de páginas
	p.SetFont("Helvetica", "", 9)
	p.AddPage()

	// Primitivas con conversión WinAnsi aplicada a cada cadena.
	cell := func(w, h float64, s, borders, align string, ln int) {
		p.CellFormat(w, h, utf8ToWinAnsi(s), borders, ln, align, false, 0, "")
	}
	multi := func(w, h float64, s, borders, align string) {
		p.MultiCell(w, h, utf8ToWinAnsi(s), borders, align, false)
	}
	// measure calcula el ancho real de lo que cell() dibujará: en modo fuente
	// núcleo fpdf mide byte a byte, así que se mide el texto ya convertido a
	// WinAnsi (idéntico a los bytes emitidos).
	measure := func(s string) float64 {
		return p.GetStringWidth(utf8ToWinAnsi(s))
	}
	// ellipsize corta con "…" lo que no cabe en una línea con la fuente
	// activa (Cell recorta sin avisar). Usa GetStringWidth: SplitText
	// infra-envuelve con medidas en mm y no recortaba a tiempo.
	ellipsize := func(s string, w float64) string {
		s = pdfSafe(s)
		if measure(s) <= w {
			return s
		}
		runes := []rune(s)
		for n := len(runes); n > 0; n-- {
			cand := string(runes[:n]) + "…"
			if measure(cand) <= w {
				return cand
			}
		}
		return "…"
	}
	// wrapLines envuelve por palabras con la métrica real de la fuente.
	wrapLines := func(s string, w float64) []string {
		s = pdfSafe(s)
		words := strings.Fields(s)
		if len(words) == 0 {
			return []string{""}
		}
		var lines []string
		cur := words[0]
		for _, word := range words[1:] {
			cand := cur + " " + word
			if measure(cand) <= w {
				cur = cand
				continue
			}
			lines = append(lines, cur)
			cur = word
		}
		return append(lines, cur)
	}

	const pageW = 180.0 // ancho útil (210 − 2×15)

	// --- Bloque QR (arriba, centrado) ---
	p.Ln(qrQuietMM)
	p.SetFont("Helvetica", "B", 11)
	cell(pageW, 5, qrLabel, "", "C", 1)
	p.Ln(qrQuietMM)

	p.RegisterImageOptionsReader("qr", fpdf.ImageOptions{ImageType: "PNG"}, bytes.NewReader(png))
	qrX := (210 - qrSizeMM) / 2
	p.ImageOptions("qr", qrX, p.GetY(), qrSizeMM, qrSizeMM, false, fpdf.ImageOptions{ImageType: "PNG"}, 0, "")
	p.Ln(qrSizeMM + qrQuietMM)
	p.SetFont("Helvetica", "", 10)
	cell(pageW, 5, qrLegend, "", "C", 1)
	p.Ln(6)

	// --- Cabecera: emisor (izq.) / datos de la factura (der.) ---
	p.SetFont("Helvetica", "B", 12)
	cell(110, 6, ellipsize(m.Seller.Name, 108), "", "L", 0)
	p.SetFont("Helvetica", "B", 13)
	cell(pageW-110, 6, "FACTURA", "", "R", 1)
	p.SetFont("Helvetica", "", 9)
	multi(110, 4.5, strings.TrimSpace(strings.Join([]string{
		"NIF: " + m.Seller.NIF,
		m.Seller.Address,
		strings.TrimSpace(m.Seller.PostCode + " " + m.Seller.Town),
		m.Seller.Province,
	}, "\n")), "", "L")
	x := 125.0
	y := p.GetY()
	p.SetXY(x, y)
	cell(pageW-110, 5, "Número: "+m.Number, "", "L", 0)
	p.SetXY(x, y+5)
	cell(pageW-110, 5, "Fecha: "+fechasDDMMAAAA(m.Issue), "", "L", 0)
	if m.InvoiceClass != "" {
		p.SetXY(x, y+10)
		cell(pageW-110, 5, "Clase: "+m.InvoiceClass, "", "L", 1)
	} else {
		p.SetXY(x, y+10)
		p.Ln(5)
	}
	p.Ln(4)

	// --- Receptor ---
	p.SetFont("Helvetica", "B", 10)
	cell(pageW, 6, "Cliente", "T", "L", 1)
	p.SetFont("Helvetica", "", 9)
	cell(60, 5, ellipsize(m.Buyer.Name, 58), "", "L", 0)
	cell(pageW-60, 5, "NIF: "+m.Buyer.NIF, "", "R", 1)
	multi(pageW, 4.5, strings.TrimSpace(strings.Join([]string{
		m.Buyer.Address,
		strings.TrimSpace(m.Buyer.PostCode + " " + m.Buyer.Town),
		m.Buyer.Province,
	}, "\n")), "", "L")
	p.Ln(2)

	// --- Centros DIR3 (si los hay) ---
	if len(m.Centres) > 0 {
		p.SetFont("Helvetica", "B", 9)
		cell(35, 6, "Rol", "TB", "L", 0)
		cell(30, 6, "Código", "TB", "L", 0)
		cell(pageW-65, 6, "Órgano", "TB", "L", 1)
		p.SetFont("Helvetica", "", 9)
		for _, c := range m.Centres {
			role := centreRoleLabels[c.Role]
			if role == "" {
				role = c.Desc
			}
			cell(35, 5.5, role, "LRTB", "L", 0)
			cell(30, 5.5, c.Code, "LRTB", "L", 0)
			cell(pageW-65, 5.5, ellipsize(c.Name, pageW-67), "LRTB", "L", 1)
		}
		p.Ln(4)
	}

	// --- Líneas ---
	p.Ln(2)
	p.SetFont("Helvetica", "B", 9)
	cell(8, 6, "Nº", "TB", "C", 0)
	cell(82, 6, "Descripción", "TB", "L", 0)
	cell(16, 6, "Cant.", "TB", "R", 0)
	cell(22, 6, "P.U.", "TB", "R", 0)
	cell(14, 6, "IVA", "TB", "R", 0)
	cell(pageW-142, 6, "Importe", "TB", "R", 1)

	p.SetFont("Helvetica", "", 9)
	for i, l := range m.Lines {
		lines := wrapLines(l.Desc, 80)
		if len(lines) == 0 {
			lines = []string{""}
		}
		h := float64(len(lines))*4.5 + 1
		y0 := p.GetY()
		if y0+h > 277 { // margen inferior de seguridad A4
			p.AddPage()
			y0 = p.GetY()
		}
		p.SetFont("Helvetica", "", 9)
		cell(8, h, fmt.Sprintf("%d", i+1), "LRTB", "C", 0)
		// Descripción multilínea en su columna (ya convertida a WinAnsi).
		x0, yDesc := p.GetX(), p.GetY()
		for j, ln := range lines {
			p.SetXY(x0, yDesc+float64(j)*4.5+0.5)
			cell(82, 4.5, ln, "", "L", 0)
		}
		p.SetXY(x0+82, yDesc)
		cell(16, h, esNum(l.Quantity), "LRTB", "R", 0)
		cell(22, h, esNum(l.UnitPrice), "LRTB", "R", 0)
		cell(14, h, esNum(l.TaxRate)+"%", "LRTB", "R", 0)
		cell(pageW-142, h, esNum(l.Gross), "LRTB", "R", 1)
	}
	p.Ln(4)

	// --- Resumen de impuestos ---
	if len(m.Taxes) > 0 {
		p.SetFont("Helvetica", "B", 9)
		cell(30, 6, "Tipo", "TB", "C", 0)
		cell(45, 6, "Base", "TB", "R", 0)
		cell(45, 6, "Cuota", "TB", "R", 1)
		p.SetFont("Helvetica", "", 9)
		for _, t := range m.Taxes {
			cell(30, 5.5, esNum(t.Rate)+"%", "LRTB", "C", 0)
			cell(45, 5.5, esNum(t.Base), "LRTB", "R", 0)
			cell(45, 5.5, esNum(t.Amount), "LRTB", "R", 1)
		}
		p.Ln(4)
	}

	// --- Totales (derecha) ---
	totW := 75.0
	totX := 15 + pageW - totW
	p.SetFont("Helvetica", "", 9)
	for _, row := range [][2]string{
		{"Base imponible", esNum(m.Totals.Gross)},
		{"Total impuestos", esNum(m.Totals.TaxOutput)},
	} {
		p.SetX(totX)
		cell(totW-30, 5, row[0], "", "L", 0)
		cell(30, 5, row[1], "", "R", 1)
	}
	if m.Totals.Withheld != "" && m.Totals.Withheld != "0.00" && m.Totals.Withheld != "0" {
		p.SetX(totX)
		cell(totW-30, 5, "Retenciones", "", "L", 0)
		cell(30, 5, esNum(m.Totals.Withheld), "", "R", 1)
	}
	p.SetX(totX)
	p.SetFont("Helvetica", "B", 11)
	cell(totW-35, 7, "TOTAL", "", "L", 0)
	cell(35, 7, esNum(m.Totals.Total)+" "+m.Currency, "", "R", 1)
	p.Ln(6)

	// --- Pago ---
	p.SetFont("Helvetica", "B", 9)
	cell(pageW, 5, "Pago", "", "L", 1)
	p.SetFont("Helvetica", "", 9)
	pay := paymentMeansLabel(m.Payment.Means)
	if m.Payment.DueDate != "" {
		pay += " · vencimiento " + fechasDDMMAAAA(m.Payment.DueDate)
	}
	cell(pageW, 5, pay, "", "L", 1)
	if m.Payment.IBAN != "" {
		cell(pageW, 5, "IBAN: "+m.Payment.IBAN, "", "L", 1)
	}

	p.SetFooterFunc(func() {
		p.SetY(-15)
		p.SetFont("Helvetica", "", 8)
		cell(pageW, 10, fmt.Sprintf("Página %d de {nb}", p.PageNo()), "", "C", 0)
	})

	var buf bytes.Buffer
	if err := p.Output(&buf); err != nil {
		return nil, fmt.Errorf("generar PDF: %w", err)
	}
	return buf.Bytes(), nil
}
