package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"strings"
)

// signerConfig es la configuración de firma del signer.
//
// Dos modos de clave de transporte (WPFE_KEY_MODE):
//
//   - "" / "env": WPFE_PRIVATE_KEY (PEM en línea o ruta) — modo histórico,
//     el operador custodia la clave (docker de desarrollo / staging).
//   - "generate": el signer genera la clave RSA-2048 en memoria al arrancar.
//     La privada NUNCA sale del proceso (en el enclave: RAM aislada) y la
//     pública se publica vía /v1/transport-key y /v1/attestation — nadie
//     (ni el dueño de la infraestructura) puede descifrar los blobs WPFE1.
//     Al no persistir, un reinicio rota la clave: volver a subir el
//     certificado en WordPress (convención v1).
//
// No hay ninguna contraseña de PKCS#12: el plugin abre el .p12 al subirlo y
// envía clave+certificado ya extraídos (bundle PEM, cifrado con WPFE1).
type signerConfig struct {
	privateKey *rsa.PrivateKey
	generated  bool // clave generada en memoria (modo "generate")
}

// transportKeyGenerated refleja el modo de la clave activa; lo usa el aviso
// de rotación en wpfe1.go.
var transportKeyGenerated bool

func loadSignerConfig() (*signerConfig, error) {
	mode := strings.TrimSpace(os.Getenv("WPFE_KEY_MODE"))
	if mode == "" {
		mode = "env"
	}

	var (
		key       *rsa.PrivateKey
		generated bool
	)
	switch mode {
	case "env":
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
		parsed, err := parseRSAPrivateKeyPEM(data)
		if err != nil {
			return nil, err
		}
		key = parsed
	case "generate":
		// Clave efímera generada aquí dentro: en modo enclave vive sólo en
		// la RAM aislada; el proceso no la escribe en ningún sitio.
		generatedKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return nil, fmt.Errorf("generar clave de transporte: %w", err)
		}
		key = generatedKey
		generated = true
	default:
		return nil, fmt.Errorf("WPFE_KEY_MODE desconocido (%q): ¿env o generate?", mode)
	}

	transportKeyGenerated = generated
	return &signerConfig{
		privateKey: key,
		generated:  generated,
	}, nil
}

// transportPublicKeyPEM devuelve la SPKI (PKIX) PEM de la clave pública de
// transporte: es lo que WordPress pega en "Clave Pública (PEM)".
func transportPublicKeyPEM(key *rsa.PrivateKey) (string, error) {
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return "", err
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})), nil
}

// transportPublicKeyDER devuelve la SPKI DER (para el campo public_key del
// documento de attestation del NSM).
func transportPublicKeyDER(key *rsa.PrivateKey) ([]byte, error) {
	return x509.MarshalPKIXPublicKey(&key.PublicKey)
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
