package main

import (
	"bytes"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const sampleInvoiceXML = `<?xml version="1.0" encoding="UTF-8"?>
<fe:Facturae xmlns:fe="http://www.facturae.gob.es/formato/Versiones/Facturaev3_2_2.xml" xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
  <FileHeader><SchemaVersion>3.2.2</SchemaVersion></FileHeader>
  <Parties>
    <SellerParty>
      <TaxIdentification>
        <PersonTypeCode>J</PersonTypeCode>
        <ResidenceTypeCode>R</ResidenceTypeCode>
        <TaxIdentificationNumber>B19995869</TaxIdentificationNumber>
      </TaxIdentification>
      <LegalEntity>
        <CorporateName>Emisor Soluciones S.L.</CorporateName>
        <AddressInSpain>
          <Address>Gran Via 1</Address><PostCode>28013</PostCode>
          <Town>Madrid</Town><Province>Madrid</Province><CountryCode>ESP</CountryCode>
        </AddressInSpain>
      </LegalEntity>
    </SellerParty>
    <BuyerParty>
      <TaxIdentification>
        <PersonTypeCode>F</PersonTypeCode>
        <ResidenceTypeCode>R</ResidenceTypeCode>
        <TaxIdentificationNumber>B37252301</TaxIdentificationNumber>
      </TaxIdentification>
      <AdministrativeCentres>
        <AdministrativeCentre>
          <CentreCode>E04921301</CentreCode>
          <RoleTypeCode>01</RoleTypeCode>
          <Name>MINISTERIO DE HACIENDA</Name>
          <CentreDescription>Oficina Contable</CentreDescription>
        </AdministrativeCentre>
        <AdministrativeCentre>
          <CentreCode>E00107204</CentreCode>
          <RoleTypeCode>03</RoleTypeCode>
          <Name>DEL.GOB. EN CATALUÑA</Name>
          <CentreDescription>Unidad Tramitadora</CentreDescription>
        </AdministrativeCentre>
      </AdministrativeCentres>
      <Individual>
        <Name>Bla</Name><FirstSurname>Prueba</FirstSurname>
        <AddressInSpain>
          <Address>Calle 1</Address><PostCode>46001</PostCode>
          <Town>Valencia</Town><Province>Valencia</Province><CountryCode>ESP</CountryCode>
        </AddressInSpain>
      </Individual>
    </BuyerParty>
  </Parties>
  <Invoices>
    <Invoice>
      <InvoiceHeader>
        <InvoiceNumber>2026-0007</InvoiceNumber>
        <InvoiceDocumentType>FC</InvoiceDocumentType>
        <InvoiceClass>OO</InvoiceClass>
      </InvoiceHeader>
      <InvoiceIssueData>
        <IssueDate>2026-10-01</IssueDate>
        <InvoiceCurrencyCode>EUR</InvoiceCurrencyCode>
        <LanguageName>es</LanguageName>
      </InvoiceIssueData>
      <TaxesOutputs>
        <Tax>
          <TaxTypeCode>01</TaxTypeCode>
          <TaxRate>21.00</TaxRate>
          <TaxableBase><TotalAmount>100.00</TotalAmount></TaxableBase>
          <TaxAmount><TotalAmount>21.00</TotalAmount></TaxAmount>
        </Tax>
      </TaxesOutputs>
      <InvoiceTotals>
        <TotalGrossAmount>100.00</TotalGrossAmount>
        <TotalGrossAmountBeforeTaxes>100.00</TotalGrossAmountBeforeTaxes>
        <TotalTaxOutputs>21.00</TotalTaxOutputs>
        <TotalTaxesWithheld>0.00</TotalTaxesWithheld>
        <InvoiceTotal>121.00</InvoiceTotal>
        <TotalOutstandingAmount>121.00</TotalOutstandingAmount>
        <TotalExecutableAmount>121.00</TotalExecutableAmount>
      </InvoiceTotals>
      <Items>
        <InvoiceLine>
          <ItemDescription>Producto &amp; servicio de prueba</ItemDescription>
          <Quantity>2</Quantity>
          <UnitPriceWithoutTax>50.00</UnitPriceWithoutTax>
          <TotalCost>100.00</TotalCost>
          <GrossAmount>100.00</GrossAmount>
          <TaxesOutputs>
            <Tax>
              <TaxTypeCode>01</TaxTypeCode>
              <TaxRate>21.00</TaxRate>
              <TaxableBase><TotalAmount>100.00</TotalAmount></TaxableBase>
              <TaxAmount><TotalAmount>21.00</TotalAmount></TaxAmount>
            </Tax>
          </TaxesOutputs>
        </InvoiceLine>
      </Items>
      <PaymentDetails>
        <Installment>
          <InstallmentDueDate>2026-11-01</InstallmentDueDate>
          <InstallmentAmount>121.00</InstallmentAmount>
          <PaymentMeans>04</PaymentMeans>
          <AccountToBeCredited><IBAN>ES9121000418450200051332</IBAN></AccountToBeCredited>
        </Installment>
      </PaymentDetails>
    </Invoice>
  </Invoices>
</fe:Facturae>`

func TestJavaURLEncode(t *testing.T) {
	cases := []struct{ in, want string }{
		{"12345678&G33", "12345678%26G33"}, // ejemplo de la spec §4
		{"89890001K", "89890001K"},
		{"01-01-2024", "01-01-2024"},
		{"241.4", "241.4"},
		{"a b", "a+b"},
		{"a/b", "a%2Fb"},
		{"a_b-c.d*", "a_b-c.d*"},
		{"100%", "100%25"},
	}
	for _, c := range cases {
		if got := javaURLEncode(c.in); got != c.want {
			t.Errorf("javaURLEncode(%q) = %q, se esperaba %q", c.in, got, c.want)
		}
	}
}

func TestBuildQRURLMatchesSpecExample(t *testing.T) {
	// Spec §4: ejemplo con numserie "&" codificado como %26.
	got := buildQRURL("https://prewww2.aeat.es/wlpl/TIKE-CONT/ValidarQR",
		"89890001K", "12345678&G33", "01-01-2024", "241.4")
	want := "https://prewww2.aeat.es/wlpl/TIKE-CONT/ValidarQR" +
		"?nif=89890001K&numserie=12345678%26G33&fecha=01-01-2024&importe=241.4"
	if got != want {
		t.Errorf("buildQRURL = %q, se esperaba %q", got, want)
	}
}

func TestParseInvoicePDFModel(t *testing.T) {
	m, err := parseInvoicePDFModel([]byte(sampleInvoiceXML))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	if m.Number != "2026-0007" {
		t.Errorf("Number = %q", m.Number)
	}
	if m.Seller.NIF != "B19995869" || m.Seller.Name != "Emisor Soluciones S.L." {
		t.Errorf("Seller = %+v", m.Seller)
	}
	if m.Buyer.NIF != "B37252301" || m.Buyer.Name != "Bla Prueba" {
		t.Errorf("Buyer = %+v", m.Buyer)
	}
	if len(m.Centres) != 2 {
		t.Fatalf("Centres = %d, se esperaban 2", len(m.Centres))
	}
	if m.Centres[0].Code != "E04921301" || m.Centres[0].Role != "01" {
		t.Errorf("Centres[0] = %+v", m.Centres[0])
	}
	if len(m.Lines) != 1 || m.Lines[0].Desc != "Producto & servicio de prueba" {
		t.Errorf("Lines = %+v", m.Lines)
	}
	if m.Totals.Total != "121.00" || m.Totals.TaxOutput != "21.00" {
		t.Errorf("Totals = %+v", m.Totals)
	}
	if m.Payment.IBAN != "ES9121000418450200051332" || m.Payment.Means != "04" {
		t.Errorf("Payment = %+v", m.Payment)
	}
	if got := fechasDDMMAAAA(m.Issue); got != "01-10-2026" {
		t.Errorf("fecha = %q", got)
	}
}

func TestParseInvoicePDFModelRejectsGarbage(t *testing.T) {
	if _, err := parseInvoicePDFModel([]byte("<html><body>oops</body></html>")); err == nil {
		t.Fatal("se esperaba error para XML que no es Facturae")
	} else if !strings.Contains(err.Error(), "Facturae") {
		t.Errorf("mensaje inesperado: %v", err)
	}
	if _, err := parseInvoicePDFModel([]byte("no es xml")); err == nil {
		t.Fatal("se esperaba error para XML mal formado")
	}
}

func TestRenderInvoicePDFSmoke(t *testing.T) {
	m, err := parseInvoicePDFModel([]byte(sampleInvoiceXML))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	pdf, err := renderInvoicePDF(m)
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	if !bytes.HasPrefix(pdf, []byte("%PDF-")) {
		t.Error("el PDF no empieza por la marca PDF")
	}
	if !bytes.Contains(pdf, []byte("%%EOF")) {
		t.Error("el PDF no tiene la marca de fin de documento")
	}
	if !bytes.Contains(pdf, []byte("/Subtype /Image")) {
		t.Error("el PDF no incrusta la imagen del QR")
	}
	if len(pdf) < 3000 {
		t.Errorf("PDF demasiado pequeño: %d bytes", len(pdf))
	}
}

func TestPDFHandler(t *testing.T) {
	srv := httptest.NewServer(newMux())
	defer srv.Close()

	post := func(body string) *http.Response {
		t.Helper()
		resp, err := http.Post(srv.URL+"/pdf", "application/json", strings.NewReader(body))
		if err != nil {
			t.Fatalf("POST /pdf: %v", err)
		}
		return resp
	}

	// Caso feliz.
	resp := post(`{"xml":"` + base64.StdEncoding.EncodeToString([]byte(sampleInvoiceXML)) + `"}`)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "application/pdf" {
		t.Errorf("Content-Type = %q", ct)
	}
	buf := new(bytes.Buffer)
	buf.ReadFrom(resp.Body)
	resp.Body.Close()
	if !bytes.HasPrefix(buf.Bytes(), []byte("%PDF-")) {
		t.Error("la respuesta no es un PDF")
	}

	// Falta xml.
	resp = post(`{}`)
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("sin xml: status = %d", resp.StatusCode)
	}
	resp.Body.Close()

	// Base64 inválido.
	resp = post(`{"xml":"!!!"}`)
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("b64: status = %d", resp.StatusCode)
	}
	resp.Body.Close()

	// XML bien formado pero no Facturae.
	resp = post(`{"xml":"` + base64.StdEncoding.EncodeToString([]byte("<x/>")) + `"}`)
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("no-facturae: status = %d", resp.StatusCode)
	}
	resp.Body.Close()

	// Método no permitido.
	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/pdf", nil)
	resp2, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET /pdf: %v", err)
	}
	if resp2.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("GET /pdf: status = %d", resp2.StatusCode)
	}
	resp2.Body.Close()
}

func TestUTF8ToWinAnsi(t *testing.T) {
	cases := []struct{ in, want string }{
		{"electrónica", "electr\xf3nica"},               // ó → 0xF3
		{"Cataluña Ñ", "Catalu\xf1a \xd1"},              // ñ/Ñ Latin-1
		{"«guion» · punto", "\xabguion\xbb \xb7 punto"}, // « » · Latin-1
		{"€100", "\x80100"},                             // euro → 0x80 en CP1252
		{"plain ascii", "plain ascii"},
		{"emoji 😀", "emoji ?"}, // no representable
	}
	for _, c := range cases {
		if got := utf8ToWinAnsi(c.in); got != c.want {
			t.Errorf("utf8ToWinAnsi(%q) = %q, se esperaba %q", c.in, got, c.want)
		}
	}
}
