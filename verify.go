package main

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha1" //nolint:gosec // se usa para verificar digests SHA-1 de la política
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"strings"
	"unicode"

	"github.com/beevik/etree"
	dsig "github.com/russellhaering/goxmldsig"
)

// URIs de algoritmos XMLDSig.
const (
	algSHA1   = "http://www.w3.org/2000/09/xmldsig#sha1"
	algSHA256 = "http://www.w3.org/2001/04/xmlenc#sha256"
	// Variante xmldsig-more: es la que FACe exige para ds:DigestMethod
	// (insight de soporte); xmlenc#sha256 se sigue reconociendo para
	// documentos ya firmados y para SigPolicyHash.
	algSHA256More = "http://www.w3.org/2001/04/xmldsig-more#sha256"
	algSHA384     = "http://www.w3.org/2001/04/xmlenc#sha384"
	algSHA512     = "http://www.w3.org/2001/04/xmlenc#sha512"

	algRSASHA1   = "http://www.w3.org/2000/09/xmldsig#rsa-sha1"
	algRSASHA256 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
	algRSASHA384 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384"
	algRSASHA512 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512"
)

// verifySignedXML recomputa, como lo haría un validador externo, todas las
// referencias y la SignatureValue del XML firmado. Cualquier discrepancia se
// devuelve como error: nunca debe escapar un XML firmado inválido.
func verifySignedXML(docBytes []byte) error {
	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(docBytes); err != nil {
		return fmt.Errorf("el documento firmado no es XML válido: %w", err)
	}
	root := doc.Root()
	if root == nil {
		return fmt.Errorf("documento sin elemento raíz")
	}
	sig := findSignature(root)
	if sig == nil {
		return fmt.Errorf("falta el elemento ds:Signature")
	}
	si := sig.SelectElement("SignedInfo")
	if si == nil {
		return fmt.Errorf("falta ds:SignedInfo")
	}
	sv := sig.SelectElement("SignatureValue")
	if sv == nil {
		return fmt.Errorf("falta ds:SignatureValue")
	}
	ki := sig.SelectElement("KeyInfo")
	if ki == nil {
		return fmt.Errorf("falta ds:KeyInfo")
	}

	if err := verifyReferences(root, sig, si); err != nil {
		return err
	}
	if err := verifySignatureValue(si, sv, ki); err != nil {
		return err
	}
	if err := verifySigningCertificate(sig); err != nil {
		return err
	}
	return verifyPolicyConstants(sig)
}

// verifyReferences comprueba el digest de cada ds:Reference.
func verifyReferences(root, sig, si *etree.Element) error {
	refs := si.SelectElements("Reference")
	if len(refs) == 0 {
		return fmt.Errorf("ds:SignedInfo sin referencias")
	}
	canon := dsig.MakeC14N10RecCanonicalizer()
	docRefSeen := false

	for _, ref := range refs {
		uriAttr := ref.SelectAttr("URI")
		if uriAttr == nil {
			return fmt.Errorf("ds:Reference sin atributo URI")
		}
		dm := ref.SelectElement("DigestMethod")
		dv := ref.SelectElement("DigestValue")
		if dm == nil || dv == nil || dm.SelectAttr("Algorithm") == nil {
			return fmt.Errorf("ds:Reference incompleto (DigestMethod/DigestValue)")
		}
		hashFn, err := hashForURI(dm.SelectAttr("Algorithm").Value)
		if err != nil {
			return fmt.Errorf("digest no soportado en %q: %w", uriAttr.Value, err)
		}

		var computed string
		if uriAttr.Value == "" {
			docRefSeen = true
			computed, err = documentDigest(root, sig, canon, hashFn)
		} else {
			id := strings.TrimPrefix(uriAttr.Value, "#")
			el := findByID(root, id)
			if el == nil {
				return fmt.Errorf("la referencia %q no apunta a ningún elemento", uriAttr.Value)
			}
			// Canonicalización inclusiva in situ: exactamente lo que hace un
			// validador sobre el nodo incrustado con sus namespaces en ámbito.
			c14n, err := canon.Canonicalize(el)
			if err != nil {
				return fmt.Errorf("canonicalizar %q: %w", uriAttr.Value, err)
			}
			computed = base64.StdEncoding.EncodeToString(hashFn(c14n))
		}
		if err != nil {
			return err
		}
		if computed != stripWS(dv.Text()) {
			return fmt.Errorf("digest incorrecto para la referencia %q", uriAttr.Value)
		}
	}
	if !docRefSeen {
		return fmt.Errorf("falta la referencia al documento (URI=\"\")")
	}
	return nil
}

// documentDigest calcula el digest del documento con la transformación
// enveloped-signature aplicada (se elimina ds:Signature y se canonicaliza).
func documentDigest(root, sig *etree.Element, canon dsig.Canonicalizer, hashFn func([]byte) []byte) (string, error) {
	tmp := root.Copy()
	sigIdx := -1
	for i, child := range tmp.Child {
		if el, ok := child.(*etree.Element); ok &&
			el.Tag == "Signature" && el.NamespaceURI() == dsigNS {
			sigIdx = i
			break
		}
	}
	if sigIdx < 0 {
		return "", fmt.Errorf("no se pudo eliminar la firma para verificar el documento")
	}
	tmp.RemoveChildAt(sigIdx)

	c14n, err := canon.Canonicalize(tmp)
	if err != nil {
		return "", fmt.Errorf("canonicalizar el documento: %w", err)
	}
	return base64.StdEncoding.EncodeToString(hashFn(c14n)), nil
}

// verifySignatureValue valida la firma sobre ds:SignedInfo con el certificado
// incluido en el propio documento (no con material local).
func verifySignatureValue(si, sv, ki *etree.Element) error {
	cm := si.SelectElement("CanonicalizationMethod")
	if cm == nil || cm.SelectAttr("Algorithm") == nil {
		return fmt.Errorf("ds:SignedInfo sin CanonicalizationMethod")
	}
	sm := si.SelectElement("SignatureMethod")
	if sm == nil || sm.SelectAttr("Algorithm") == nil {
		return fmt.Errorf("ds:SignedInfo sin SignatureMethod")
	}
	sigHash, err := hashForSignatureMethod(sm.SelectAttr("Algorithm").Value)
	if err != nil {
		return err
	}

	x509Data := ki.SelectElement("X509Data")
	if x509Data == nil {
		return fmt.Errorf("ds:KeyInfo sin ds:X509Data")
	}
	certEl := x509Data.SelectElement("X509Certificate")
	if certEl == nil {
		return fmt.Errorf("ds:X509Data sin ds:X509Certificate")
	}
	der, err := base64.StdEncoding.DecodeString(stripWS(certEl.Text()))
	if err != nil {
		return fmt.Errorf("ds:X509Certificate no es base64 válido: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return fmt.Errorf("ds:X509Certificate no es un certificado válido: %w", err)
	}
	pub, ok := cert.PublicKey.(*rsa.PublicKey)
	if !ok {
		return fmt.Errorf("el certificado no contiene una clave RSA")
	}

	sigVal, err := base64.StdEncoding.DecodeString(stripWS(sv.Text()))
	if err != nil {
		return fmt.Errorf("ds:SignatureValue no es base64 válido: %w", err)
	}

	canon := dsig.MakeC14N10RecCanonicalizer()
	c14nSI, err := canon.Canonicalize(si)
	if err != nil {
		return fmt.Errorf("canonicalizar ds:SignedInfo: %w", err)
	}
	digest := sigHash.New()
	digest.Write(c14nSI) //nolint:errcheck
	if err := rsa.VerifyPKCS1v15(pub, sigHash, digest.Sum(nil), sigVal); err != nil {
		return fmt.Errorf("SignatureValue no valida contra SignedInfo: %w", err)
	}
	return nil
}

// verifySigningCertificate comprueba el digest SHA-512 del certificado y la
// coherencia del número de serie en xades:SigningCertificate.
func verifySigningCertificate(sig *etree.Element) error {
	sp := qualifyingPath(sig, "SignedProperties")
	if sp == nil {
		return fmt.Errorf("falta xades:SignedProperties")
	}
	ssp := sp.SelectElement("SignedSignatureProperties")
	if ssp == nil {
		return fmt.Errorf("falta xades:SignedSignatureProperties")
	}
	sc := ssp.SelectElement("SigningCertificate")
	if sc == nil {
		return fmt.Errorf("falta xades:SigningCertificate")
	}
	certs := sc.SelectElements("Cert")
	if len(certs) == 0 {
		return fmt.Errorf("xades:SigningCertificate sin xades:Cert")
	}
	certDigest := certs[0].SelectElement("CertDigest")
	issuerSerial := certs[0].SelectElement("IssuerSerial")
	if certDigest == nil || issuerSerial == nil {
		return fmt.Errorf("xades:Cert incompleto (CertDigest/IssuerSerial)")
	}
	dm := certDigest.SelectElement("DigestMethod")
	dv := certDigest.SelectElement("DigestValue")
	if dm == nil || dv == nil || dm.SelectAttr("Algorithm") == nil {
		return fmt.Errorf("xades:CertDigest incompleto")
	}
	hashFn, err := hashForURI(dm.SelectAttr("Algorithm").Value)
	if err != nil {
		return err
	}

	ki := sig.SelectElement("KeyInfo")
	x509Data := ki.SelectElement("X509Data")
	certEl := x509Data.SelectElement("X509Certificate")
	der, err := base64.StdEncoding.DecodeString(stripWS(certEl.Text()))
	if err != nil {
		return fmt.Errorf("ds:X509Certificate no es base64 válido: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return fmt.Errorf("ds:X509Certificate no es un certificado válido: %w", err)
	}

	if got := base64.StdEncoding.EncodeToString(hashFn(cert.Raw)); got != stripWS(dv.Text()) {
		return fmt.Errorf("xades:CertDigest no coincide con el certificado")
	}

	name := issuerSerial.SelectElement("X509IssuerName")
	serial := issuerSerial.SelectElement("X509SerialNumber")
	if name == nil || serial == nil || strings.TrimSpace(name.Text()) == "" {
		return fmt.Errorf("xades:IssuerSerial incompleto")
	}
	if stripWS(serial.Text()) != cert.SerialNumber.String() {
		return fmt.Errorf("xades:X509SerialNumber no coincide con el certificado")
	}
	return nil
}

// verifyPolicyConstants defiende las constantes de la política de firma
// FacturaE v3.1 contra desajustes de configuración.
func verifyPolicyConstants(sig *etree.Element) error {
	sp := qualifyingPath(sig, "SignedProperties")
	if sp == nil {
		return fmt.Errorf("falta xades:SignedProperties")
	}
	ssp := sp.SelectElement("SignedSignatureProperties")
	policy := ssp.SelectElement("SignaturePolicyIdentifier")
	if policy == nil {
		return fmt.Errorf("falta xades:SignaturePolicyIdentifier")
	}
	id := qualifyingSub(policy, "SignaturePolicyId", "SigPolicyId", "Identifier")
	if id == nil || strings.TrimSpace(id.Text()) != policyURL {
		return fmt.Errorf("la identificación de la política no es la de FacturaE v3.1")
	}
	hash := qualifyingSub(policy, "SignaturePolicyId", "SigPolicyHash")
	if hash == nil {
		return fmt.Errorf("falta xades:SigPolicyHash")
	}
	dm := hash.SelectElement("DigestMethod")
	dv := hash.SelectElement("DigestValue")
	if dm == nil || dv == nil || dm.SelectAttr("Algorithm") == nil {
		return fmt.Errorf("xades:SigPolicyHash incompleto")
	}
	if dm.SelectAttr("Algorithm").Value != policyAlgorithm {
		return fmt.Errorf("algoritmo del hash de política inesperado")
	}
	if stripWS(dv.Text()) != policyHash {
		return fmt.Errorf("hash de la política inesperado")
	}
	return nil
}

func hashForURI(uri string) (func([]byte) []byte, error) {
	switch uri {
	case algSHA1:
		return func(b []byte) []byte { h := sha1.Sum(b); return h[:] }, nil
	case algSHA256, algSHA256More:
		return func(b []byte) []byte { h := sha256.Sum256(b); return h[:] }, nil
	case algSHA384:
		return func(b []byte) []byte { h := sha512.Sum384(b); return h[:] }, nil
	case algSHA512:
		return func(b []byte) []byte { h := sha512.Sum512(b); return h[:] }, nil
	default:
		return nil, fmt.Errorf("algoritmo de digest desconocido (%q)", uri)
	}
}

func hashForSignatureMethod(uri string) (crypto.Hash, error) {
	switch uri {
	case algRSASHA1:
		return crypto.SHA1, nil
	case algRSASHA256:
		return crypto.SHA256, nil
	case algRSASHA384:
		return crypto.SHA384, nil
	case algRSASHA512:
		return crypto.SHA512, nil
	default:
		return 0, fmt.Errorf("método de firma desconocido (%q)", uri)
	}
}

// findByID busca un elemento con atributo Id dentro del árbol.
func findByID(root *etree.Element, id string) *etree.Element {
	if attr := root.SelectAttr("Id"); attr != nil && attr.Value == id {
		return root
	}
	for _, child := range root.Child {
		if el, ok := child.(*etree.Element); ok {
			if found := findByID(el, id); found != nil {
				return found
			}
		}
	}
	return nil
}

// qualifyingPath recorre ds:Object/ds:QualifyingProperties/<name>.
func qualifyingPath(sig *etree.Element, name string) *etree.Element {
	obj := sig.SelectElement("Object")
	if obj == nil {
		return nil
	}
	qp := obj.SelectElement("QualifyingProperties")
	if qp == nil {
		return nil
	}
	return qp.SelectElement(name)
}

func qualifyingSub(start *etree.Element, path ...string) *etree.Element {
	cur := start
	for _, p := range path {
		if cur == nil {
			return nil
		}
		cur = cur.SelectElement(p)
	}
	return cur
}

// stripWS elimina todo espacio en blanco (los digests pueden llevar saltos de
// línea de relleno).
func stripWS(s string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsSpace(r) {
			return -1
		}
		return r
	}, s)
}
