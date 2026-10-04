package main

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/beevik/etree"
	"github.com/invopop/xmldsig"
)

const (
	policyURL         = "http://www.facturae.es/politica_de_firma_formato_facturae/politica_de_firma_formato_facturae_v3_1.pdf"
	policyDescription = "Política de Firma FacturaE v3.1"
	// Perfil literal de la aplicación oficial de Facturae (inv-working.xsig,
	// validado por el validador AOC): SHA-1 en toda la estructura, incluido
	// SigPolicyHash, con el digest de la política v3.1 pre-2025.
	// (La hipótesis previa "FACe exige sha256" venía de rechazos que en
	// realidad eran del número de versión 3.2.2; el .xsig oficial con sha1
	// pasa todas las validaciones.)
	policyAlgorithm = "http://www.w3.org/2000/09/xmldsig#sha1"
	policyHash      = "Ohixl6upD6av8N7pEvDABhEL6hM="
	signerRole      = "emisor"
	dataDescription = "Factura electrónica"
)

// inputError identifica errores causados por la entrada: respuesta HTTP 400.
type inputError struct{ msg string }

func (e *inputError) Error() string { return e.msg }

func inputErrf(format string, a ...any) error {
	return &inputError{msg: fmt.Sprintf(format, a...)}
}

// verificationError identifica fallos de la autocomprobación: HTTP 500.
type verificationError struct{ err error }

func (e *verificationError) Error() string {
	return "autocomprobación de la firma fallida: " + e.err.Error()
}

func (e *verificationError) Unwrap() error { return e.err }

// signXML firma un documento FacturaE con XAdES-B-B de forma clásica (ver
// xades.go) y devuelve el XML firmado ya autocomprobado.
func signXML(input string, cert *xmldsig.Certificate) (string, error) {
	inBytes := []byte(input)
	if len(bytes.TrimSpace(inBytes)) == 0 {
		return "", inputErrf("xml vacío")
	}
	if cert == nil {
		return "", errors.New("certificado nulo")
	}

	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(inBytes); err != nil {
		return "", inputErrf("xml no válido: %v", err)
	}
	root := doc.Root()
	if root == nil {
		return "", inputErrf("xml sin elemento raíz")
	}
	if findSignature(root) != nil {
		return "", inputErrf("el documento ya contiene una firma")
	}

	sigBytes, err := buildXAdESSignature(inBytes, root, cert)
	if err != nil {
		var ie *inputError
		if errors.As(err, &ie) {
			return "", err
		}
		return "", fmt.Errorf("generar firma: %w", err)
	}

	out, err := spliceSignature(inBytes, root, sigBytes)
	if err != nil {
		return "", err
	}

	if err := verifySignedXML(out); err != nil {
		return "", &verificationError{err: err}
	}
	return string(out), nil
}

// spliceSignature inserta la firma como último hijo de la raíz sin re-serializar
// el documento original: los bytes de la factura se conservan intactos, por lo que
// el digest del documento entero es estable por construcción.
func spliceSignature(in []byte, root *etree.Element, sig []byte) ([]byte, error) {
	qname := root.Tag
	if root.Space != "" {
		qname = root.Space + ":" + root.Tag
	}
	closeTag := "</" + qname + ">"

	idx := bytes.LastIndex(in, []byte(closeTag))
	if idx < 0 {
		return nil, inputErrf("no se encontró la etiqueta de cierre </%s>", qname)
	}
	if len(bytes.TrimSpace(in[idx+len(closeTag):])) > 0 {
		return nil, inputErrf("contenido epílogo tras </%s> no soportado", qname)
	}

	out := make([]byte, 0, len(in)+len(sig))
	out = append(out, in[:idx]...)
	out = append(out, sig...)
	out = append(out, in[idx:]...)
	return out, nil
}

// findSignature localiza un elemento ds:Signature hijo directo de root.
func findSignature(root *etree.Element) *etree.Element {
	for _, child := range root.Child {
		if el, ok := child.(*etree.Element); ok &&
			el.Tag == "Signature" && el.NamespaceURI() == dsigNS {
			return el
		}
	}
	return nil
}
