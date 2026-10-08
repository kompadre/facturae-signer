package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"facturae-signer/internal/hostid"
	"facturae-signer/internal/keystore"
)

// signerConfig es la configuración de firma del signer.
//
// Tres modos de clave de transporte (WPFE_KEY_MODE):
//
//   - "" / "env": WPFE_PRIVATE_KEY (PEM en línea o ruta) — modo histórico,
//     el operador custodia la clave (docker de desarrollo / staging).
//   - "generate": el signer genera la clave RSA-2048 en memoria al arrancar.
//     La privada NUNCA sale del proceso (en el enclave: RAM aislada) y la
//     pública se publica vía /v1/transport-key y /v1/attestation — nadie
//     (ni el dueño de la infraestructura) puede descifrar los blobs WPFE1.
//     Al no persistir, un reinicio rota la clave: volver a subir el
//     certificado en WordPress (convención v1).
//   - "persistent": modo VPS. La clave se genera una vez y se guarda en el
//     keystore cifrada con un master derivado de la identidad de la máquina
//     (ver internal/keystore). Además hay identidad x509 de host
//     (internal/hostid): con ella se firma el vínculo que ata la pública de
//     transporte a ESTE host, que es lo que el plugin fija en Ajustes.
//
// No hay ninguna contraseña de PKCS#12: el plugin abre el .p12 al subirlo y
// envía clave+certificado ya extraídos (bundle PEM, cifrado con WPFE1).
type signerConfig struct {
	privateKey *rsa.PrivateKey
	generated  bool   // clave generada en memoria (modo "generate")
	keyMode    string // "env" | "generate" | "persistent"
	host       *hostid.Identity
	rewrapped  bool   // se re-envolvió el keystore al arrancar (rotación de cert)
	keystore   string // ruta del keystore (para doctor/logs)
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
	case "persistent":
		// Modo VPS: keystore cifrado + identidad de host (vínculo).
		return loadPersistent()
	default:
		return nil, fmt.Errorf("WPFE_KEY_MODE desconocido (%q): ¿env, generate o persistent?", mode)
	}

	transportKeyGenerated = generated
	return &signerConfig{
		privateKey: key,
		generated:  generated,
		keyMode:    mode,
	}, nil
}

// dataDir es el directorio de datos del signer (keystore + identidad de host).
func dataDir() string {
	if d := strings.TrimSpace(os.Getenv("WPFE_DATA_DIR")); d != "" {
		return d
	}
	return "/var/lib/facturae-signer"
}

// hostIdentityPaths devuelve (cert, clave) de la identidad del host; con
// WPFE_HOST_CERT/WPFE_HOST_KEY apunta a un par existente (p. ej. Let's
// Encrypt), si no, al par generado por init.
func hostIdentityPaths() (string, string) {
	dir := dataDir()
	cert := strings.TrimSpace(os.Getenv("WPFE_HOST_CERT"))
	key := strings.TrimSpace(os.Getenv("WPFE_HOST_KEY"))
	if cert == "" {
		cert = filepath.Join(dir, "host.cert")
	}
	if key == "" {
		key = filepath.Join(dir, "host.key")
	}
	return cert, key
}

// keystorePath es la ruta del keystore (WPFE_KEYSTORE la cambia).
func keystorePath() string {
	if p := strings.TrimSpace(os.Getenv("WPFE_KEYSTORE")); p != "" {
		return p
	}
	return filepath.Join(dataDir(), "keystore.bin")
}

// loadPersistent carga (o da de alta) el keystore del modo VPS. La identidad
// de host se crea también en la primera pasada: sin SPKI no hay master.
func loadPersistent() (*signerConfig, error) {
	hostCert, hostKey := hostIdentityPaths()
	hostname, _ := os.Hostname()
	host, err := hostid.LoadOrCreate(hostCert, hostKey, hostname)
	if err != nil {
		return nil, fmt.Errorf("identidad de host: %w", err)
	}

	ksPath := keystorePath()
	key, rewrapped, err := keystore.LoadOrCreate(ksPath, host.SPKI)
	if err != nil {
		return nil, err
	}

	transportKeyGenerated = false
	return &signerConfig{
		privateKey: key,
		generated:  false,
		keyMode:    "persistent",
		host:       host,
		rewrapped:  rewrapped,
		keystore:   ksPath,
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
