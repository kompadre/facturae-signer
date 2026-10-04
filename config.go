package main

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"strings"
)

// signerConfig es la configuración de firma cargada del entorno.
//
// WPFE_PRIVATE_KEY: PEM de la clave privada RSA (contenido en línea si contiene
//
//	"-----BEGIN", o ruta de fichero) que descifra el blob WPFE1 de la petición.
//
// No hay ninguna contraseña de PKCS#12: el plugin abre el .p12 al subirlo y
// envía clave+certificado ya extraídos (bundle PEM, cifrado con WPFE1).
type signerConfig struct {
	privateKey *rsa.PrivateKey
}

func loadConfigFromEnv() (*signerConfig, error) {
	raw := os.Getenv("WPFE_PRIVATE_KEY")
	if strings.TrimSpace(raw) == "" {
		return nil, errors.New("falta la variable de entorno WPFE_PRIVATE_KEY")
	}

	data := []byte(raw)
	if !strings.Contains(raw, "-----BEGIN") {
		b, err := os.ReadFile(raw)
		if err != nil {
			return nil, fmt.Errorf("lectura de WPFE_PRIVATE_KEY (%s): %w", raw, err)
		}
		data = b
	}

	key, err := parseRSAPrivateKeyPEM(data)
	if err != nil {
		return nil, err
	}

	return &signerConfig{
		privateKey: key,
	}, nil
}

func parseRSAPrivateKeyPEM(data []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("WPFE_PRIVATE_KEY no es un PEM válido")
	}
	if enc := block.Headers["Proc-Type"]; strings.Contains(enc, "ENCRYPTED") {
		return nil, errors.New("WPFE_PRIVATE_KEY: el PEM está cifrada; usa una clave sin cifrar")
	}

	switch block.Type {
	case "RSA PRIVATE KEY":
		key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("clave PKCS#1 ilegible: %w", err)
		}
		return key, nil
	case "PRIVATE KEY":
		parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("clave PKCS#8 ilegible: %w", err)
		}
		key, ok := parsed.(*rsa.PrivateKey)
		if !ok {
			return nil, errors.New("WPFE_PRIVATE_KEY debe ser una clave RSA")
		}
		return key, nil
	default:
		return nil, fmt.Errorf("WPFE_PRIVATE_KEY: tipo de bloque no soportado (%q)", block.Type)
	}
}
