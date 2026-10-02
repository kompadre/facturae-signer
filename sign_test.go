package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"errors"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/beevik/etree"
	"github.com/invopop/xmldsig"
	"software.sslmate.com/src/go-pkcs12"
)

const sampleInvoice = `<?xml version="1.0" encoding="UTF-8"?>
<fe:Facturae xmlns:fe="http://www.facturae.gob.es/formato/Versiones/Facturaev3_2_2.xml" xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
  <FileHeader>
    <SchemaVersion>3.2.2</SchemaVersion>
    <Modality>I</Modality>
    <InvoiceIssuerType>EM</InvoiceIssuerType>
    <Batch>
      <BatchIdentifier>2026-0001</BatchIdentifier>
      <InvoicesCount>1</InvoicesCount>
    </Batch>
  </FileHeader>
  <Invoices>
    <Invoice>
      <InvoiceHeader>
        <InvoiceNumber>2026-0001</InvoiceNumber>
        <InvoiceDocumentType>FC</InvoiceDocumentType>
        <InvoiceClass>OO</InvoiceClass>
      </InvoiceHeader>
      <InvoiceIssueData>
        <IssueDate>2026-09-30</IssueDate>
        <InvoiceCurrencyCode>EUR</InvoiceCurrencyCode>
        <LanguageName>es</LanguageName>
      </InvoiceIssueData>
      <InvoiceTotals>
        <TotalGrossAmount>21.00</TotalGrossAmount>
        <InvoiceTotal>21.00</InvoiceTotal>
      </InvoiceTotals>
      <Items>
        <InvoiceLine>
          <ItemDescription>Albarán nº 1 &amp; "prueba" — año 2026</ItemDescription>
          <Quantity>1</Quantity>
          <TotalCost>21.00</TotalCost>
          <GrossAmount>21.00</GrossAmount>
          <TaxesOutputs/>
        </InvoiceLine>
      </Items>
    </Invoice>
  </Invoices>
</fe:Facturae>`

const sampleInvoiceFB2B = `<?xml version="1.0" encoding="UTF-8"?>
<fe:Facturae xmlns:fe="http://www.facturae.gob.es/formato/Versiones/Facturaev3_2_2.xml" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" xmlns:fb2b="http://www.facturae.gob.es/Facturae/faceb2b/extensions/Facturae_v1_1" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
  <FileHeader>
    <SchemaVersion>3.2.2</SchemaVersion>
    <Modality>I</Modality>
    <InvoiceIssuerType>EM</InvoiceIssuerType>
  </FileHeader>
  <fb2b:FacturaeB2BExtension>
    <fb2b:FacturaeB2BURI>https://example.test/factura/2026-0001</fb2b:FacturaeB2BURI>
  </fb2b:FacturaeB2BExtension>
  <Invoices>
    <Invoice>
      <InvoiceHeader>
        <InvoiceNumber>2026-0001</InvoiceNumber>
      </InvoiceHeader>
    </Invoice>
  </Invoices>
</fe:Facturae>`

const unprefixedInvoice = `<?xml version="1.0" encoding="UTF-8"?>
<Facturae xmlns="http://www.facturae.gob.es/formato/Versiones/Facturaev3_2_2.xml">
  <FileHeader>
    <SchemaVersion>3.2.2</SchemaVersion>
  </FileHeader>
</Facturae>`

// newTestCert genera un certificado autosignado + p12 y lo carga con la misma
// ruta que usa el servicio en producción (LoadCertificateFromBytes).
func newTestCert(t *testing.T, password string) (*xmldsig.Certificate, []byte) {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generar clave: %v", err)
	}
	p12, err := mkP12(t, key, password)
	if err != nil {
		t.Fatalf("crear p12: %v", err)
	}
	cert, err := xmldsig.LoadCertificateFromBytes(p12, password)
	if err != nil {
		t.Fatalf("cargar p12: %v", err)
	}
	return cert, p12
}

func mkP12(t *testing.T, key *rsa.PrivateKey, password string) ([]byte, error) {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject: pkix.Name{
			CommonName:   "WPFacturaE Test Signer",
			Organization: []string{"WPFacturaE Tests"},
			Country:      []string{"ES"},
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return pkcs12.Modern2023.Encode(key, cert, nil, password)
}

func TestSignXMLProducesVerifiableXAdES(t *testing.T) {
	cert, _ := newTestCert(t, "test-pass")

	out, err := signXML(sampleInvoice, cert)
	if err != nil {
		t.Fatalf("signXML: %v", err)
	}
	// signXML ya autocomprobó; lo hacemos explícito también aquí.
	if err := verifySignedXML([]byte(out)); err != nil {
		t.Fatalf("verifySignedXML: %v", err)
	}
	assertSignatureStructure(t, out, sampleInvoice)
}

func TestSignXMLWithFB2BNamespaces(t *testing.T) {
	cert, _ := newTestCert(t, "test-pass")

	out, err := signXML(sampleInvoiceFB2B, cert)
	if err != nil {
		t.Fatalf("signXML: %v", err)
	}
	if err := verifySignedXML([]byte(out)); err != nil {
		t.Fatalf("verifySignedXML: %v", err)
	}
	if !strings.Contains(out, "xmlns:fb2b=") {
		t.Error("el namespace fb2b desapareció")
	}
	assertSignatureStructure(t, out, sampleInvoiceFB2B)
}

func TestSignXMLUnprefixedRoot(t *testing.T) {
	cert, _ := newTestCert(t, "test-pass")

	out, err := signXML(unprefixedInvoice, cert)
	if err != nil {
		t.Fatalf("signXML: %v", err)
	}
	if err := verifySignedXML([]byte(out)); err != nil {
		t.Fatalf("verifySignedXML: %v", err)
	}
	if !strings.Contains(out, "</Facturae>") {
		t.Error("la etiqueta de cierre raíz no se conservó")
	}
	assertSignatureStructure(t, out, unprefixedInvoice)
}

func TestSignXMLPreservesOriginalBytes(t *testing.T) {
	cert, _ := newTestCert(t, "test-pass")

	out, err := signXML(sampleInvoice, cert)
	if err != nil {
		t.Fatalf("signXML: %v", err)
	}

	start := strings.Index(out, "<ds:Signature")
	endTag := "</ds:Signature>"
	end := strings.Index(out, endTag)
	if start < 0 || end < 0 {
		t.Fatalf("firma no encontrada en la salida")
	}
	end += len(endTag)

	restored := out[:start] + out[end:]
	if restored != sampleInvoice {
		t.Error("los bytes originales de la factura no se conservan intactos")
	}
}

func TestSignXMLRejectsMalformedInput(t *testing.T) {
	cert, _ := newTestCert(t, "test-pass")
	for _, in := range []string{"", "   ", "<not-closed", "<a></b>"} {
		_, err := signXML(in, cert)
		if err == nil {
			t.Errorf("entrada %q: se esperaba error", in)
			continue
		}
		var ie *inputError
		if !errors.As(err, &ie) {
			t.Errorf("entrada %q: se esperaba inputError, se obtuvo %T", in, err)
		}
	}
}

func TestSignXMLRejectsAlreadySigned(t *testing.T) {
	cert, _ := newTestCert(t, "test-pass")
	out, err := signXML(sampleInvoice, cert)
	if err != nil {
		t.Fatalf("signXML: %v", err)
	}
	_, err = signXML(out, cert)
	if err == nil || !strings.Contains(err.Error(), "ya contiene una firma") {
		t.Errorf("se esperaba rechazo de documento ya firmado, se obtuvo %v", err)
	}
}

func TestSignXMLRejectsEpilogContent(t *testing.T) {
	cert, _ := newTestCert(t, "test-pass")
	in := unprefixedInvoice + "<!-- comentario epílogo -->\n"
	if _, err := signXML(in, cert); err == nil {
		t.Fatal("se esperaba rechazo de epílogo con contenido")
	} else {
		var ie *inputError
		if !errors.As(err, &ie) {
			t.Errorf("se esperaba inputError, se obtuvo %T", err)
		}
	}
}

func TestVerifyDetectsTamperedDocument(t *testing.T) {
	cert, _ := newTestCert(t, "test-pass")
	out, err := signXML(sampleInvoice, cert)
	if err != nil {
		t.Fatalf("signXML: %v", err)
	}

	tampered := strings.Replace(out, "<InvoiceNumber>2026-0001", "<InvoiceNumber>2026-0002", 1)
	if err := verifySignedXML([]byte(tampered)); err == nil {
		t.Fatal("la verificación no detectó un documento alterado")
	}

	tamperedPolicy := strings.Replace(out, policyHash, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", 1)
	if err := verifySignedXML([]byte(tamperedPolicy)); err == nil {
		t.Fatal("la verificación no detectó el hash de política alterado")
	}

	// Alterar el contenido de SignatureValue debe romper la verificación.
	i := strings.Index(out, "<ds:SignatureValue")
	if i < 0 {
		t.Fatal("falta ds:SignatureValue")
	}
	open := strings.Index(out[i:], ">")
	if open < 0 {
		t.Fatal("estructura inesperada")
	}
	bodyStart := i + open + 1
	k := strings.Index(out[bodyStart:], "</ds:SignatureValue>")
	if k < 0 {
		t.Fatal("falta el cierre de ds:SignatureValue")
	}
	broken := out[:bodyStart] + strings.Repeat("A", 8) + out[bodyStart+k:]
	if err := verifySignedXML([]byte(broken)); err == nil {
		t.Fatal("la verificación no detectó una SignatureValue alterada")
	}
}

// assertSignatureStructure comprueba la forma XAdES esperada y la conservación
// del documento original.
func assertSignatureStructure(t *testing.T, out, original string) {
	t.Helper()

	doc := etree.NewDocument()
	if err := doc.ReadFromString(out); err != nil {
		t.Fatalf("la salida no es XML bien formado: %v", err)
	}
	root := doc.Root()
	if root.Space != "fe" && root.Space != "" {
		t.Errorf("prefijo raíz = %q, se esperaba fe o vacío", root.Space)
	}

	sig := findSignature(root)
	if sig == nil {
		t.Fatal("falta ds:Signature como hijo directo de la raíz")
	}
	// Signature debe ser el último hijo elemento (lo exige el XSD de FacturaE).
	lastElem := -1
	sigIdx := -1
	for i, child := range root.Child {
		if el, ok := child.(*etree.Element); ok {
			lastElem = i
			if el == sig {
				sigIdx = i
			}
		}
	}
	if sigIdx != lastElem {
		t.Error("ds:Signature no es el último elemento hijo de la raíz")
	}

	if sig.NamespaceURI() != dsigNS {
		t.Errorf("namespace de Signature = %q, se esperaba %q", sig.NamespaceURI(), dsigNS)
	}

	si := sig.SelectElement("SignedInfo")
	if si == nil {
		t.Fatal("falta ds:SignedInfo")
	}
	if si.SelectAttrValue("Id", "") == "" {
		t.Error("ds:SignedInfo debe llevar atributo Id (forma clásica)")
	}

	// Orden y algoritmos de SignedInfo.
	kids := si.ChildElements()
	if len(kids) < 5 {
		t.Fatalf("ds:SignedInfo con %d hijos, se esperaban >= 5", len(kids))
	}
	if kids[0].Tag != "CanonicalizationMethod" || kids[1].Tag != "SignatureMethod" {
		t.Errorf("orden de SignedInfo inesperado: %s, %s", kids[0].Tag, kids[1].Tag)
	}
	if got := kids[0].SelectAttrValue("Algorithm", ""); got != "http://www.w3.org/TR/2001/REC-xml-c14n-20010315" {
		t.Errorf("CanonicalizationMethod = %q", got)
	}
	if got := kids[1].SelectAttrValue("Algorithm", ""); got != algRSASHA256 {
		t.Errorf("SignatureMethod = %q, se esperaba %q", got, algRSASHA256)
	}

	refs := si.SelectElements("Reference")
	if len(refs) != 3 {
		t.Fatalf("se esperaban 3 referencias, hay %d", len(refs))
	}
	// Orden clásico aceptado por FACe: SignedProperties, KeyInfo, documento.
	if refs[0].SelectAttrValue("Type", "") != "http://uri.etsi.org/01903#SignedProperties" {
		t.Errorf("refs[0].Type = %q", refs[0].SelectAttrValue("Type", ""))
	}
	if !strings.HasPrefix(refs[0].SelectAttrValue("URI", ""), "#Signature-") {
		t.Errorf("refs[0].URI = %q, se esperaba #Signature-…-SignedProperties", refs[0].SelectAttrValue("URI", ""))
	}
	if refs[0].SelectAttrValue("Id", "") == "" {
		t.Error("la referencia a SignedProperties debe llevar Id")
	}
	if refs[0].SelectElement("Transforms") != nil {
		t.Error("la referencia a SignedProperties no debe llevar transformaciones")
	}
	if !strings.HasPrefix(refs[1].SelectAttrValue("URI", ""), "#Certificate") {
		t.Errorf("refs[1].URI = %q, se esperaba #Certificate…", refs[1].SelectAttrValue("URI", ""))
	}
	if refs[1].SelectAttrValue("Type", "") != "" {
		t.Errorf("refs[1].Type = %q, se esperaba sin Type", refs[1].SelectAttrValue("Type", ""))
	}
	if refs[2].SelectAttrValue("URI", "") != "" {
		t.Errorf("refs[2].URI = %q, se esperaba vacío (documento)", refs[2].SelectAttrValue("URI", ""))
	}
	if refs[2].SelectAttrValue("Type", "") != "http://www.w3.org/2000/09/xmldsig#Object" {
		t.Errorf("refs[2].Type = %q", refs[2].SelectAttrValue("Type", ""))
	}
	transforms := refs[2].SelectElement("Transforms")
	if transforms == nil {
		t.Fatal("la referencia al documento debe llevar transformaciones")
	}
	tr := transforms.SelectElements("Transform")
	if len(tr) != 2 ||
		tr[0].SelectAttrValue("Algorithm", "") != "http://www.w3.org/2000/09/xmldsig#enveloped-signature" ||
		tr[1].SelectAttrValue("Algorithm", "") != "http://www.w3.org/TR/2001/REC-xml-c14n-20010315" {
		t.Errorf("la referencia al documento debe listar enveloped + C14N (%d transforms)", len(tr))
	}
	for i, ref := range refs {
		dm := ref.SelectElement("DigestMethod")
		if dm == nil || dm.SelectAttrValue("Algorithm", "") != algSHA256X {
			t.Errorf("refs[%d].DigestMethod != sha256 (xmldsig-more)", i)
		}
		if ref.SelectElement("DigestValue") == nil {
			t.Errorf("refs[%d] sin DigestValue", i)
		}
	}

	// KeyInfo: certificado + RSAKeyValue.
	ki := sig.SelectElement("KeyInfo")
	if ki == nil {
		t.Fatal("falta ds:KeyInfo")
	}
	x509Data := ki.SelectElement("X509Data")
	if x509Data == nil || x509Data.SelectElement("X509Certificate") == nil {
		t.Fatal("falta ds:X509Certificate")
	}
	kv := ki.SelectElement("KeyValue")
	if kv == nil || kv.SelectElement("RSAKeyValue") == nil {
		t.Fatal("falta ds:RSAKeyValue")
	}
	if exp := kv.FindElement("RSAKeyValue/Exponent"); exp == nil || exp.Text() != "AQAB" {
		t.Error("ds:Exponent debe ser AQAB")
	}

	// XAdES.
	sp := qualifyingPath(sig, "SignedProperties")
	if sp == nil {
		t.Fatal("falta xades:SignedProperties")
	}
	if sp.SelectAttrValue("Id", "") == "" {
		t.Error("xades:SignedProperties debe llevar Id")
	}
	qp := sig.SelectElement("Object").SelectElement("QualifyingProperties")
	if qp.SelectAttrValue("Target", "") != "#"+sig.SelectAttrValue("Id", "") {
		t.Errorf("Target de QualifyingProperties = %q", qp.SelectAttrValue("Target", ""))
	}
	if qp.SelectAttr("Id") != nil {
		t.Error("xades:QualifyingProperties no debe llevar Id (forma clásica)")
	}

	ssp := sp.SelectElement("SignedSignatureProperties")
	st := ssp.SelectElement("SigningTime")
	if st == nil {
		t.Fatal("falta xades:SigningTime")
	}
	if _, err := time.Parse(time.RFC3339, st.Text()); err != nil {
		t.Errorf("SigningTime %q no es RFC3339: %v", st.Text(), err)
	}
	if sc := ssp.SelectElement("SigningCertificate"); sc == nil {
		t.Error("falta xades:SigningCertificate")
	}
	role := ssp.SelectElement("SignerRole")
	if role == nil {
		t.Fatal("falta xades:SignerRole")
	}
	if cr := role.FindElement("ClaimedRoles/ClaimedRole"); cr == nil || cr.Text() != "emisor" {
		t.Errorf("ClaimedRole = %q, se esperaba emisor", cr.Text())
	}
	if err := verifyPolicyConstants(sig); err != nil {
		t.Errorf("política de firma: %v", err)
	}

	sdp := sp.SelectElement("SignedDataObjectProperties")
	if sdp == nil {
		t.Fatal("falta xades:SignedDataObjectProperties")
	}
	dof := sdp.SelectElement("DataObjectFormat")
	if dof == nil {
		t.Fatal("falta xades:DataObjectFormat")
	}
	if ref := dof.SelectAttrValue("ObjectReference", ""); !strings.HasPrefix(ref, "#Reference-") {
		t.Errorf("ObjectReference = %q", ref)
	}
	if mime := dof.SelectElement("MimeType"); mime == nil || mime.Text() != "text/xml" {
		t.Error("DataObjectFormat/MimeType debe ser text/xml")
	}
	ident := dof.FindElement("ObjectIdentifier/Identifier")
	if ident == nil {
		t.Fatal("falta xades:ObjectIdentifier")
	}
	if ident.SelectAttrValue("Qualifier", "") != "OIDAsURN" || ident.Text() != "urn:oid:1.2.840.10003.5.109.10" {
		t.Errorf("ObjectIdentifier = %q (%q)", ident.Text(), ident.SelectAttrValue("Qualifier", ""))
	}

	// Ids únicos en todo el documento.
	seen := map[string]bool{}
	var walk func(*etree.Element)
	walk = func(e *etree.Element) {
		if a := e.SelectAttr("Id"); a != nil {
			if seen[a.Value] {
				t.Errorf("Id duplicado: %q", a.Value)
			}
			seen[a.Value] = true
		}
		for _, ch := range e.Child {
			if child, ok := ch.(*etree.Element); ok {
				walk(child)
			}
		}
	}
	walk(root)
	if len(seen) == 0 {
		t.Error("no se encontró ningún Id")
	}

	// El contenido original sigue presente (cabecera conservada).
	if !strings.Contains(out, original[:60]) {
		t.Error("la cabecera XML original desapareció")
	}

	// El certificado incrustado es base64 de un DER parseable.
	certB64 := strings.TrimSpace(x509Data.SelectElement("X509Certificate").Text())
	der, err := base64.StdEncoding.DecodeString(certB64)
	if err != nil {
		t.Fatalf("X509Certificate no es base64: %v", err)
	}
	if _, err := x509.ParseCertificate(der); err != nil {
		t.Fatalf("X509Certificate no es un certificado: %v", err)
	}
}

func TestFormatIssuerDN(t *testing.T) {
	cases := []struct{ in, want string }{
		{"CN=AC FNMT Usuarios,O=FNMT-RCM,C=ES", "CN=AC FNMT Usuarios, O=FNMT-RCM, C=ES"},
		{"CN=Foo, O=Bar, C=ES", "CN=Foo, O=Bar, C=ES"},               // idempotente
		{`CN=ACME\, S.L.,O=Foo,C=ES`, `CN=ACME\, S.L., O=Foo, C=ES`}, // coma escapada
	}
	for _, c := range cases {
		if got := formatIssuerDN(c.in); got != c.want {
			t.Errorf("formatIssuerDN(%q) = %q, se esperaba %q", c.in, got, c.want)
		}
	}
}

// newChainedTestCert genera CA + hoja firmada por la CA en un p12 (como el
// de un DNIe real, con cadena) y lo carga por la ruta de producción.
func newChainedTestCert(t *testing.T, password string) *xmldsig.Certificate {
	t.Helper()

	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("clave CA: %v", err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test CA", Country: []string{"ES"}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("cert CA: %v", err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatalf("parse CA: %v", err)
	}

	leafKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("clave hoja: %v", err)
	}
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "Test Leaf", Country: []string{"ES"}},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, caCert, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("cert hoja: %v", err)
	}
	leafCert, err := x509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatalf("parse hoja: %v", err)
	}

	p12, err := pkcs12.Modern2023.Encode(leafKey, leafCert, []*x509.Certificate{caCert}, password)
	if err != nil {
		t.Fatalf("p12: %v", err)
	}
	cert, err := xmldsig.LoadCertificateFromBytes(p12, password)
	if err != nil {
		t.Fatalf("cargar p12: %v", err)
	}
	return cert
}

// Regresión: con cadena (DNIe real) los certs van en ELEMENTOS SEPARADOS;
// concatenarlos en un solo X509Certificate rompe el base64 (padding) y la
// autocomprobación fallaba con "no es base64 válido".
func TestSignXMLWithCertificateChain(t *testing.T) {
	cert := newChainedTestCert(t, "chain-pass")
	if len(cert.CaChain) == 0 {
		t.Fatal("el p12 de prueba no tiene cadena (CaChain vacía)")
	}

	out, err := signXML(sampleInvoice, cert)
	if err != nil {
		t.Fatalf("signXML con cadena: %v", err)
	}
	if err := verifySignedXML([]byte(out)); err != nil {
		t.Fatalf("verifySignedXML con cadena: %v", err)
	}
	if n := strings.Count(out, "<ds:X509Certificate>"); n != 1+len(cert.CaChain) {
		t.Errorf("X509Certificate elements = %d, se esperaban %d (hoja + CAs)", n, 1+len(cert.CaChain))
	}
}
