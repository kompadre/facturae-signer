package main

import (
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/beevik/etree"
	"github.com/invopop/xmldsig"
	dsig "github.com/russellhaering/goxmldsig"
)

const (
	xadesNS = "http://uri.etsi.org/01903/v1.3.2#"

	algC14N10 = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315"
	// FACe exige la variante xmldsig-more para ds:DigestMethod (insight de
	// soporte); xmlenc#sha256 se conserva en SigPolicyHash por instrucción
	// explícita de la plantilla canónica que dio ese digest.
	algSHA256X              = "http://www.w3.org/2001/04/xmldsig-more#sha256"
	algRSASHA256X           = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
	algEnveloped            = "http://www.w3.org/2000/09/xmldsig#enveloped-signature"
	refTypeSignedProperties = "http://uri.etsi.org/01903#SignedProperties"
	refTypeObject           = "http://www.w3.org/2000/09/xmldsig#Object"
)

// signatureIDs agrupa los Ids de una firma (un nonce por firma; patrones de
// la forma clásica de FacturaE: Signature…, SignedPropertiesID…,
// Reference-ID-…, Certificate…).
type signatureIDs struct {
	signature        string
	signedInfo       string
	signedPropsRef   string
	signatureValue   string
	certificate      string
	dataRef          string
	signedProperties string
	object           string
}

func newSignatureIDs() (signatureIDs, error) {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return signatureIDs{}, fmt.Errorf("nonce: %w", err)
	}
	n := hex.EncodeToString(b[:])
	sig := "Signature-" + n
	return signatureIDs{
		signature:        sig,
		signedInfo:       "Signature-SignedInfo-" + n,
		signedPropsRef:   "SignedPropertiesID-" + n,
		signatureValue:   "SignatureValue-" + n,
		certificate:      "Certificate-" + n,
		dataRef:          "Reference-ID-" + n,
		signedProperties: sig + "-SignedProperties",
		object:           sig + "-Object",
	}, nil
}

// rootNamespaces devuelve los prefijos declarados en la raíz ("" = xmlns por
// defecto). Es el ámbito que heredan los fragmentos incrustados, más los
// prefijos que declaramos en <ds:Signature>.
func rootNamespaces(root *etree.Element) map[string]string {
	scope := make(map[string]string)
	for _, a := range root.Attr {
		if a.Space == "xmlns" {
			scope[a.Key] = a.Value
		} else if a.Space == "" && a.Key == "xmlns" {
			scope[""] = a.Value
		}
	}
	// <ds:Signature> declara ds y xades siempre: es el ámbito real en el que
	// incrustamos SignedInfo/KeyInfo/SignedProperties.
	scope["ds"] = dsigNS
	scope["xades"] = xadesNS
	return scope
}

// canonicalizeFragment inyecta el ámbito de namespaces en el elemento raíz
// del fragmento y lo canonicaliza (C14N 1.0 inclusivo), produciendo exactamente
// los bytes que un validador calcularía sobre el nodo ya incrustado.
func canonicalizeFragment(fragmentXML string, scope map[string]string) ([]byte, error) {
	doc := etree.NewDocument()
	if err := doc.ReadFromString(fragmentXML); err != nil {
		return nil, fmt.Errorf("parsear fragmento: %w", err)
	}
	r := doc.Root()
	if r == nil {
		return nil, fmt.Errorf("fragmento sin raíz")
	}
	for prefix, uri := range scope {
		attr := etree.Attr{Space: "xmlns", Key: prefix, Value: uri}
		if prefix == "" {
			attr = etree.Attr{Space: "", Key: "xmlns", Value: uri}
		}
		present := false
		for _, a := range r.Attr {
			if a.Space == attr.Space && a.Key == attr.Key {
				present = true
				break
			}
		}
		if !present {
			r.Attr = append(r.Attr, attr)
		}
	}
	return dsig.MakeC14N10RecCanonicalizer().Canonicalize(r)
}

func sha256B64(data []byte) string {
	sum := sha256.Sum256(data)
	return base64.StdEncoding.EncodeToString(sum[:])
}

// prettyB64 parte la base64 en líneas de 76 caracteres (chunk_split de PHP).
func prettyB64(s string) string {
	var sb strings.Builder
	for len(s) > 76 {
		sb.WriteString(s[:76])
		sb.WriteString("\n")
		s = s[76:]
	}
	sb.WriteString(s)
	sb.WriteString("\n")
	return sb.String()
}

func escapeXMLText(s string) string {
	r := strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;")
	return r.Replace(s)
}

// formatIssuerDN formatea el DN del emisor al estilo del .xsig de ejemplo
// validado por AEAT ("CN=…, OU=…, O=…, C=…"): RDNs separados por ", ".
// Respeta comas escapadas (\,) dentro de los valores.
func formatIssuerDN(issuer string) string {
	var b strings.Builder
	b.Grow(len(issuer) + 8)
	escaped := false
	for i := 0; i < len(issuer); i++ {
		c := issuer[i]
		if escaped {
			b.WriteByte(c)
			escaped = false
			continue
		}
		if c == '\\' {
			b.WriteByte(c)
			escaped = true
			continue
		}
		if c == ',' {
			b.WriteString(", ")
			// Salta un espacio ya presente tras la coma (idempotente).
			if i+1 < len(issuer) && issuer[i+1] == ' ' {
				i++
			}
			continue
		}
		b.WriteByte(c)
	}
	return b.String()
}

// buildXAdESSignature genera un <ds:Signature> XAdES-B-B con la forma clásica
// aceptada por el validador de FACe:
//
//   - SignatureMethod rsa-sha256 y digests SHA-256 con URI xmldsig-more
//     (requisito FACe; SigPolicyHash conserva xmlenc por plantilla);
//   - referencias en orden SignedProperties → KeyInfo → documento;
//   - la referencia al documento lista enveloped + C14N explícitas;
//   - SignedProperties sin transformaciones;
//   - SignedInfo con Id; xmlns:ds y xmlns:xades declarados en la firma;
//   - QualifyingProperties solo con Target.
//
// Los digests se calculan sobre canonicalización inclusiva con el ámbito real
// (namespaces de la raíz + ds + xades); verifySignedXML revalida el resultado
// incrustado antes de devolverlo.
func buildXAdESSignature(input []byte, root *etree.Element, cert *xmldsig.Certificate) ([]byte, error) {
	ids, err := newSignatureIDs()
	if err != nil {
		return nil, err
	}
	scope := rootNamespaces(root)
	canon := dsig.MakeC14N10RecCanonicalizer()

	// --- referencia al documento (antes de insertar la firma) ---
	c14nDoc, err := canon.Canonicalize(root)
	if err != nil {
		return nil, fmt.Errorf("canonicalizar documento: %w", err)
	}
	docDigest := sha256B64(c14nDoc)

	// --- <xades:SignedProperties> ---
	// Formato con offset horario (no "Z"), como exige el ejemplo validado
	// de AEAT: 2019-09-27T11:40:28+02:00.
	signingTime := time.Now().Format("2006-01-02T15:04:05-07:00")
	certFingerprint, err := cert.Fingerprint(crypto.SHA256)
	if err != nil {
		return nil, fmt.Errorf("huella del certificado: %w", err)
	}
	spXML := fmt.Sprintf(
		`<xades:SignedProperties Id="%s">`+
			`<xades:SignedSignatureProperties>`+
			`<xades:SigningTime>%s</xades:SigningTime>`+
			`<xades:SigningCertificate><xades:Cert>`+
			`<xades:CertDigest>`+
			`<ds:DigestMethod Algorithm="%s"></ds:DigestMethod>`+
			`<ds:DigestValue>%s</ds:DigestValue>`+
			`</xades:CertDigest>`+
			`<xades:IssuerSerial>`+
			`<ds:X509IssuerName>%s</ds:X509IssuerName>`+
			`<ds:X509SerialNumber>%s</ds:X509SerialNumber>`+
			`</xades:IssuerSerial>`+
			`</xades:Cert></xades:SigningCertificate>`+
			`<xades:SignaturePolicyIdentifier><xades:SignaturePolicyId>`+
			`<xades:SigPolicyId>`+
			`<xades:Identifier>%s</xades:Identifier>`+
			`<xades:Description>%s</xades:Description>`+
			`</xades:SigPolicyId>`+
			`<xades:SigPolicyHash>`+
			`<ds:DigestMethod Algorithm="%s"></ds:DigestMethod>`+
			`<ds:DigestValue>%s</ds:DigestValue>`+
			`</xades:SigPolicyHash>`+
			`</xades:SignaturePolicyId></xades:SignaturePolicyIdentifier>`+
			`<xades:SignerRole><xades:ClaimedRoles><xades:ClaimedRole>%s</xades:ClaimedRole></xades:ClaimedRoles></xades:SignerRole>`+
			`</xades:SignedSignatureProperties>`+
			`<xades:SignedDataObjectProperties>`+
			`<xades:DataObjectFormat ObjectReference="#%s">`+
			`<xades:Description>%s</xades:Description>`+
			`<xades:ObjectIdentifier>`+
			`<xades:Identifier Qualifier="OIDAsURN">urn:oid:1.2.840.10003.5.109.10</xades:Identifier>`+
			`</xades:ObjectIdentifier>`+
			`<xades:MimeType>text/xml</xades:MimeType>`+
			`</xades:DataObjectFormat>`+
			`</xades:SignedDataObjectProperties>`+
			`</xades:SignedProperties>`,
		ids.signedProperties,
		signingTime,
		algSHA256X,
		certFingerprint,
		escapeXMLText(formatIssuerDN(cert.Issuer())),
		cert.SerialNumber(),
		policyURL,
		policyDescription,
		policyAlgorithm,
		policyHash,
		signerRole,
		ids.dataRef,
		dataDescription,
	)
	spC14n, err := canonicalizeFragment(spXML, scope)
	if err != nil {
		return nil, fmt.Errorf("canonicalizar SignedProperties: %w", err)
	}
	spDigest := sha256B64(spC14n)

	// --- <ds:KeyInfo> ---
	keyInfo := cert.PrivateKeyInfo()
	if keyInfo == nil || keyInfo.Algorithm != xmldsig.KeyAlgorithmRSA {
		return nil, inputErrf("el certificado no contiene una clave RSA")
	}
	// Una cadena se emite como varios <ds:X509Certificate> (hoja + CAs):
	// concatenarlos en un solo tag uniría segmentos base64 con padding y
	// la autocomprobación fallaría con "no es base64 válido".
	var certs strings.Builder
	writeCert := func(b64 string) {
		certs.WriteString("<ds:X509Certificate>")
		certs.WriteString(prettyB64(b64))
		certs.WriteString("</ds:X509Certificate>")
	}
	writeCert(cert.NakedPEM())
	for _, ca := range cert.CaChain {
		writeCert(xmldsig.NakedPEM(ca))
	}
	kiXML := fmt.Sprintf(
		`<ds:KeyInfo Id="%s">`+
			`<ds:X509Data>%s</ds:X509Data>`+
			`<ds:KeyValue><ds:RSAKeyValue>`+
			`<ds:Modulus>%s</ds:Modulus>`+
			`<ds:Exponent>%s</ds:Exponent>`+
			`</ds:RSAKeyValue></ds:KeyValue>`+
			`</ds:KeyInfo>`,
		ids.certificate,
		certs.String(),
		prettyB64(keyInfo.Modulus),
		keyInfo.Exponent,
	)
	kiC14n, err := canonicalizeFragment(kiXML, scope)
	if err != nil {
		return nil, fmt.Errorf("canonicalizar KeyInfo: %w", err)
	}
	kiDigest := sha256B64(kiC14n)

	// --- <ds:SignedInfo> (orden: SignedProperties, KeyInfo, documento) ---
	siXML := fmt.Sprintf(
		`<ds:SignedInfo Id="%s">`+
			`<ds:CanonicalizationMethod Algorithm="%s"></ds:CanonicalizationMethod>`+
			`<ds:SignatureMethod Algorithm="%s"></ds:SignatureMethod>`+
			`<ds:Reference Id="%s" Type="%s" URI="#%s">`+
			`<ds:DigestMethod Algorithm="%s"></ds:DigestMethod>`+
			`<ds:DigestValue>%s</ds:DigestValue>`+
			`</ds:Reference>`+
			`<ds:Reference URI="#%s">`+
			`<ds:DigestMethod Algorithm="%s"></ds:DigestMethod>`+
			`<ds:DigestValue>%s</ds:DigestValue>`+
			`</ds:Reference>`+
			`<ds:Reference Id="%s" Type="%s" URI="">`+
			// FACe exige transformaciones explícitas: enveloped + C14N.
			`<ds:Transforms>`+
			`<ds:Transform Algorithm="%s"></ds:Transform>`+
			`<ds:Transform Algorithm="%s"></ds:Transform>`+
			`</ds:Transforms>`+
			`<ds:DigestMethod Algorithm="%s"></ds:DigestMethod>`+
			`<ds:DigestValue>%s</ds:DigestValue>`+
			`</ds:Reference>`+
			`</ds:SignedInfo>`,
		ids.signedInfo,
		algC14N10,
		algRSASHA256X,
		ids.signedPropsRef, refTypeSignedProperties, ids.signedProperties,
		algSHA256X, spDigest,
		ids.certificate,
		algSHA256X, kiDigest,
		ids.dataRef, refTypeObject,
		algEnveloped,
		algC14N10,
		algSHA256X, docDigest,
	)
	siC14n, err := canonicalizeFragment(siXML, scope)
	if err != nil {
		return nil, fmt.Errorf("canonicalizar SignedInfo: %w", err)
	}
	sigB64, err := cert.Sign(string(siC14n), crypto.SHA256, false)
	if err != nil {
		return nil, fmt.Errorf("firmar SignedInfo: %w", err)
	}

	// --- <ds:Signature> completo ---
	sigXML := fmt.Sprintf(
		`<ds:Signature xmlns:ds="%s" xmlns:xades="%s" Id="%s">`+
			`%s`+
			`<ds:SignatureValue Id="%s">%s</ds:SignatureValue>`+
			`%s`+
			`<ds:Object Id="%s">`+
			`<xades:QualifyingProperties Target="#%s">%s</xades:QualifyingProperties>`+
			`</ds:Object>`+
			`</ds:Signature>`,
		dsigNS, xadesNS, ids.signature,
		siXML,
		ids.signatureValue, sigB64,
		kiXML,
		ids.object,
		ids.signature, spXML,
	)
	return []byte(sigXML), nil
}
