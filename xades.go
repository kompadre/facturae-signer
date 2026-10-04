package main

import (
	"crypto"
	"crypto/rand"
	"crypto/sha1" //nolint:gosec // SHA-1 exigido por el perfil oficial AOC
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
	// Perfil literal del .xsig de la aplicación oficial de Facturae
	// (referencia: inv-working.xsig, validada por el validador AOC):
	// rsa-sha1 y digests SHA-1 en TODA la estructura XAdES, incluido
	// SigPolicyHash (Ohixl6up…). Los URIs sha1/rsa-sha1 y el hash de la
	// política viven en verify.go / sign.go (misma package).
	algEnveloped            = "http://www.w3.org/2000/09/xmldsig#enveloped-signature"
	refTypeSignedProperties = "http://uri.etsi.org/01903#SignedProperties"
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
	// <ds:Signature> declara ds y etsi siempre: es el ámbito real en el que
	// incrustamos SignedInfo/KeyInfo/SignedProperties (prefijo etsi como en
	// el .xsig oficial).
	scope["ds"] = dsigNS
	scope["etsi"] = xadesNS
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

func sha1B64(data []byte) string {
	sum := sha1.Sum(data)
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

// formatIssuerDN formatea el DN del emisor como la aplicación oficial:
// RDNs separados por "," SIN espacio (RFC 2253), p. ej.
// "CN=AC FNMT Usuarios,OU=Ceres,O=FNMT-RCM,C=ES".
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
			b.WriteByte(',')
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

// buildXAdESSignature genera un <ds:Signature> XAdES-B-B con la forma literal
// del .xsig de la aplicación oficial de Facturae (inv-working.xsig, validado
// por el validador AOC):
//
//   - SignatureMethod rsa-sha1 y digests SHA-1 en todas las referencias,
//     CertDigest y SigPolicyHash (Ohixl6up…);
//   - referencias en orden SignedProperties → KeyInfo → documento;
//   - la referencia al documento solo lista enveloped (sin Type, sin C14N
//     explícita), como la oficial;
//   - KeyInfo con la hoja sola + RSAKeyValue (sin cadena);
//   - DataObjectFormat con Description + MimeType (sin ObjectIdentifier);
//   - SignedProperties con Id; xmlns:ds y xmlns:etsi declarados en la firma;
//   - QualifyingProperties solo con Target.
//
// Los digests se calculan sobre canonicalización inclusiva con el ámbito real
// (namespaces de la raíz + ds + etsi); verifySignedXML revalida el resultado
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
	docDigest := sha1B64(c14nDoc)

	// --- <etsi:SignedProperties> ---
	// Formato con offset horario (no "Z"), como exige el ejemplo validado
	// de AEAT: 2019-09-27T11:40:28+02:00.
	signingTime := time.Now().Format("2006-01-02T15:04:05-07:00")
	certFingerprint, err := cert.Fingerprint(crypto.SHA1)
	if err != nil {
		return nil, fmt.Errorf("huella del certificado: %w", err)
	}
	spXML := fmt.Sprintf(
		`<etsi:SignedProperties Id="%s">`+
			`<etsi:SignedSignatureProperties>`+
			`<etsi:SigningTime>%s</etsi:SigningTime>`+
			`<etsi:SigningCertificate><etsi:Cert>`+
			`<etsi:CertDigest>`+
			`<ds:DigestMethod Algorithm="%s"></ds:DigestMethod>`+
			`<ds:DigestValue>%s</ds:DigestValue>`+
			`</etsi:CertDigest>`+
			`<etsi:IssuerSerial>`+
			`<ds:X509IssuerName>%s</ds:X509IssuerName>`+
			`<ds:X509SerialNumber>%s</ds:X509SerialNumber>`+
			`</etsi:IssuerSerial>`+
			`</etsi:Cert></etsi:SigningCertificate>`+
			`<etsi:SignaturePolicyIdentifier><etsi:SignaturePolicyId>`+
			`<etsi:SigPolicyId>`+
			`<etsi:Identifier>%s</etsi:Identifier>`+
			`<etsi:Description>%s</etsi:Description>`+
			`</etsi:SigPolicyId>`+
			`<etsi:SigPolicyHash>`+
			`<ds:DigestMethod Algorithm="%s"></ds:DigestMethod>`+
			`<ds:DigestValue>%s</ds:DigestValue>`+
			`</etsi:SigPolicyHash>`+
			`</etsi:SignaturePolicyId></etsi:SignaturePolicyIdentifier>`+
			`<etsi:SignerRole><etsi:ClaimedRoles><etsi:ClaimedRole>%s</etsi:ClaimedRole></etsi:ClaimedRoles></etsi:SignerRole>`+
			`</etsi:SignedSignatureProperties>`+
			`<etsi:SignedDataObjectProperties>`+
			`<etsi:DataObjectFormat ObjectReference="#%s">`+
			`<etsi:Description>%s</etsi:Description>`+
			`<etsi:MimeType>text/xml</etsi:MimeType>`+
			`</etsi:DataObjectFormat>`+
			`</etsi:SignedDataObjectProperties>`+
			`</etsi:SignedProperties>`,
		ids.signedProperties,
		signingTime,
		algSHA1,
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
	spDigest := sha1B64(spC14n)

	// --- <ds:KeyInfo> ---
	keyInfo := cert.PrivateKeyInfo()
	if keyInfo == nil || keyInfo.Algorithm != xmldsig.KeyAlgorithmRSA {
		return nil, inputErrf("el certificado no contiene una clave RSA")
	}
	// Como la aplicación oficial: solo la hoja (sin cadena de CAs); la
	// cadena concatenada en un solo tag rompería el base64 de todos modos.
	var certs strings.Builder
	certs.WriteString("<ds:X509Certificate>")
	certs.WriteString(prettyB64(cert.NakedPEM()))
	certs.WriteString("</ds:X509Certificate>")
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
	kiDigest := sha1B64(kiC14n)

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
			`<ds:Reference Id="%s" URI="">`+
			// Forma oficial: solo enveloped, sin Type en la referencia.
			`<ds:Transforms>`+
			`<ds:Transform Algorithm="%s"></ds:Transform>`+
			`</ds:Transforms>`+
			`<ds:DigestMethod Algorithm="%s"></ds:DigestMethod>`+
			`<ds:DigestValue>%s</ds:DigestValue>`+
			`</ds:Reference>`+
			`</ds:SignedInfo>`,
		ids.signedInfo,
		algC14N10,
		algRSASHA1,
		ids.signedPropsRef, refTypeSignedProperties, ids.signedProperties,
		algSHA1, spDigest,
		ids.certificate,
		algSHA1, kiDigest,
		ids.dataRef,
		algEnveloped,
		algSHA1, docDigest,
	)
	siC14n, err := canonicalizeFragment(siXML, scope)
	if err != nil {
		return nil, fmt.Errorf("canonicalizar SignedInfo: %w", err)
	}
	sigB64, err := cert.Sign(string(siC14n), crypto.SHA1, false)
	if err != nil {
		return nil, fmt.Errorf("firmar SignedInfo: %w", err)
	}

	// --- <ds:Signature> completo ---
	sigXML := fmt.Sprintf(
		`<ds:Signature xmlns:ds="%s" xmlns:etsi="%s" Id="%s">`+
			`%s`+
			`<ds:SignatureValue Id="%s">%s</ds:SignatureValue>`+
			`%s`+
			`<ds:Object Id="%s">`+
			`<etsi:QualifyingProperties Target="#%s">%s</etsi:QualifyingProperties>`+
			`</ds:Object>`+
			`</ds:Signature>`,
		dsigNS, xadesNS, ids.signature,
		siXML,
		ids.signatureValue, prettyB64(sigB64),
		kiXML,
		ids.object,
		ids.signature, spXML,
	)
	return []byte(sigXML), nil
}
