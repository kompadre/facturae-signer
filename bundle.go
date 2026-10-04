package main

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"strings"

	"github.com/invopop/xmldsig"
)

// keyBundle es el material de firma ya abierto: el plugin extrae clave y
// certificado del PKCS#12 al subirlo (la contraseña se usa allí, en
// WordPress, y no se guarda) y envía este bundle PEM cifrado bajo WPFE1.
// El signer no conoce ninguna contraseña de PKCS#12.
type keyBundle struct {
	signing *xmldsig.Certificate
	key     crypto.Signer
	leaf    *x509.Certificate
	cas     []*x509.Certificate
}

// parseKeyBundle parsea el bundle PEM (clave privada + certificado hoja +
// cadena). Un PKCS#12 en bruto (versiones antiguas del plugin) se rechaza
// con un mensaje que pide volver a subir el certificado con su contraseña.
func parseKeyBundle(data []byte) (*keyBundle, error) {
	if !bytes.Contains(data, []byte("-----BEGIN")) {
		return nil, inputErrf("certificate: no es un bundle PEM; si el certificado se subió con una versión anterior (PKCS#12 sin abrir), vuelve a subirlo indicando su contraseña")
	}

	block, rest := pem.Decode(data)
	if block == nil {
		return nil, inputErrf("certificate: bundle PEM ilegible")
	}
	key, err := parseBundleKey(block)
	if err != nil {
		return nil, err
	}

	var certs []*x509.Certificate
	for len(rest) > 0 {
		var b *pem.Block
		b, rest = pem.Decode(rest)
		if b == nil {
			break
		}
		if b.Type != "CERTIFICATE" {
			continue
		}
		c, err := x509.ParseCertificate(b.Bytes)
		if err != nil {
			return nil, inputErrf("certificate: certificado del bundle ilegible: %v", err)
		}
		certs = append(certs, c)
	}
	if len(certs) == 0 {
		return nil, inputErrf("certificate: el bundle no contiene certificado")
	}

	// El primer CERTIFICATE del bundle es la hoja (contrato con el plugin);
	// el resto es la cadena emisora.
	signing, err := xmldsig.NewCertificate(certs[0], key)
	if err != nil {
		return nil, inputErrf("certificate: %v", err)
	}
	signing.CaChain = certs[1:]

	return &keyBundle{
		signing: signing,
		key:     key,
		leaf:    certs[0],
		cas:     certs[1:],
	}, nil
}

func parseBundleKey(block *pem.Block) (crypto.Signer, error) {
	if strings.Contains(block.Headers["Proc-Type"], "ENCRYPTED") {
		return nil, inputErrf("certificate: la clave privada del bundle está cifrada con contraseña (no soportado)")
	}

	var (
		parsed any
		err    error
	)
	switch block.Type {
	case "RSA PRIVATE KEY":
		parsed, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	case "PRIVATE KEY":
		parsed, err = x509.ParsePKCS8PrivateKey(block.Bytes)
	case "EC PRIVATE KEY":
		parsed, err = x509.ParseECPrivateKey(block.Bytes)
	default:
		return nil, inputErrf("certificate: bloque de clave no soportado (%q)", block.Type)
	}
	if err != nil {
		return nil, inputErrf("certificate: clave privada ilegible: %v", err)
	}

	signer, ok := parsed.(crypto.Signer)
	if !ok {
		return nil, inputErrf("certificate: tipo de clave no soportado")
	}
	return signer, nil
}
