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
// PKCS12_PASSWORD (literal, puede estar vacía) o PKCS12_PASSWORD_FILE (ruta al
// fichero con la contraseña): contraseña del PKCS#12 que viaja cifrado en la
// petición.
type signerConfig struct {
	privateKey *rsa.PrivateKey
	password   string
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

	password, err := loadPassword()
	if err != nil {
		return nil, err
	}
	return &signerConfig{
		privateKey: key,
		password:   password,
	}, nil
}

func loadPassword() (string, error) {
	if path := os.Getenv("PKCS12_PASSWORD_FILE"); path != "" {
		data, err := os.ReadFile(path)
		if err != nil {
			return "", fmt.Errorf("lectura de PKCS12_PASSWORD_FILE (%s): %w", path, err)
		}
		return strings.TrimRight(string(data), "\r\n"), nil
	}
	return os.Getenv("PKCS12_PASSWORD"), nil
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
