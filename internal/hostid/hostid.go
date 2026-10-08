// Package hostid gestiona la identidad x509 del host y el VÍNCULO (binding)
// que ata la clave de transporte pública a ESTE host.
//
// El plugin no confía en un nombre de dominio (un /etc/hosts manipulado no
// autentica nada): confía en la huella del SPKI de esta identidad, fijada en
// Ajustes la primera vez (TOFU) o pegada por el operador. Para que esa
// huella signifique algo, el host demuestra que posee la identidad firmando
// el vínculo con su clave privada; quien dote de una identidad falsa no puede
// producir un vínculo válido bajo la huella fijada.
//
// Identidad por defecto: pareja ECDSA P-256 auto-firmada generada en el alta
// (`init`), estable de por vida (una rotación del certificado Let's Encrypt
// no debe romper la fijación). Si el operador quiere además cruzar-firmar con
// el certificado TLS del sitio, se carga esa identidad aparte
// (Load + SignBinding) y se sirve como `cert_binding`.
package hostid

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"time"
)

// Algoritmos de firma del vínculo (se anuncian en el JSON; el cliente elige
// la verificación según la clave).
const (
	AlgECDSAP256 = "ecdsa-p256-sha256"
	AlgRSAPKCS1  = "rsa-pkcs1v15-sha256"

	bindingLabel = "wpfe-binding/v1"
)

var (
	ErrNoIdentity   = errors.New("hostid: no hay identidad del host (ejecuta wpfe-sign init)")
	ErrHalfIdentity = errors.New("hostid: hay clave o certificado pero no los dos; no regenero a ciegas (rompería la huella fijada)")
	ErrVerify       = errors.New("hostid: firma de vínculo no válida")
)

// Identity es la identidad x509 cargada (host propia o ACME, opcional).
type Identity struct {
	Cert        *x509.Certificate
	Key         crypto.Signer
	SPKI        []byte // SubjectPublicKeyInfo DER
	Fingerprint string // "sha256:<hex>" del SPKI: lo que fija WordPress
}

// Fingerprint devuelve la huella del SPKI en formato "sha256:<hex>".
func Fingerprint(spki []byte) string {
	sum := sha256.Sum256(spki)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// BindingPayload construye los bytes firmados del vínculo. Canonizado y con
// separación de dominio: etiqueta + SPKI de transporte + SPKI del host + instante.
func BindingPayload(transportSPKI, hostSPKI []byte, at time.Time) []byte {
	return []byte(bindingLabel + "|" +
		base64.RawStdEncoding.EncodeToString(transportSPKI) + "|" +
		base64.RawStdEncoding.EncodeToString(hostSPKI) + "|" +
		at.UTC().Format(time.RFC3339))
}

// LoadOrCreate carga la identidad del host; si NO existe ninguna de las dos
// mitades, genera la pareja (ECDSA P-256, auto-firmada, 10 años) y la
// persiste (clave 0600, cert 0644). Si existe una mitad suelta, falla: no se
// regenera porque eso cambiaría la huella que el plugin ya ha fijado.
func LoadOrCreate(certPath, keyPath, commonName string) (*Identity, error) {
	_, certErr := os.Stat(certPath)
	_, keyErr := os.Stat(keyPath)
	certExists := certErr == nil
	keyExists := keyErr == nil

	if certExists && keyExists {
		return Load(certPath, keyPath)
	}
	if certExists || keyExists {
		return nil, ErrHalfIdentity
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("hostid: generar clave: %w", err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("hostid: serial: %w", err)
	}
	if commonName == "" {
		commonName = "facturae-signer host"
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: commonName, Organization: []string{"facturae-signer"}},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, fmt.Errorf("hostid: auto-firmar: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("hostid: parsear cert: %w", err)
	}

	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("hostid: serializar clave: %w", err)
	}
	if err := writePEM(keyPath, "PRIVATE KEY", keyDER, 0o600); err != nil {
		return nil, err
	}
	if err := writePEM(certPath, "CERTIFICATE", der, 0o644); err != nil {
		return nil, err
	}
	return FromCert(cert, key)
}

// Load lee una identidad existente (por ejemplo el par TLS de Let's Encrypt).
func Load(certPath, keyPath string) (*Identity, error) {
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, fmt.Errorf("hostid: leer cert: %w", err)
	}
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("hostid: leer clave: %w", err)
	}
	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil || certBlock.Type != "CERTIFICATE" {
		return nil, errors.New("hostid: el fichero de certificado no es un PEM CERTIFICATE")
	}
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("hostid: cert ilegible: %w", err)
	}
	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return nil, errors.New("hostid: la clave no es PEM")
	}
	var signer crypto.Signer
	switch keyBlock.Type {
	case "EC PRIVATE KEY":
		k, err := x509.ParseECPrivateKey(keyBlock.Bytes)
		if err != nil {
			return nil, fmt.Errorf("hostid: clave EC ilegible: %w", err)
		}
		signer = k
	case "RSA PRIVATE KEY":
		k, err := x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
		if err != nil {
			return nil, fmt.Errorf("hostid: clave RSA ilegible: %w", err)
		}
		signer = k
	case "PRIVATE KEY":
		k, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
		if err != nil {
			return nil, fmt.Errorf("hostid: clave PKCS#8 ilegible: %w", err)
		}
		s, ok := k.(crypto.Signer)
		if !ok {
			return nil, errors.New("hostid: la clave no es firmante")
		}
		signer = s
	default:
		return nil, fmt.Errorf("hostid: tipo de bloque de clave no soportado (%q)", keyBlock.Type)
	}
	return FromCert(cert, signer)
}

// FromCert construye la identidad desde un cert ya parseado y su clave.
func FromCert(cert *x509.Certificate, key crypto.Signer) (*Identity, error) {
	spki, err := x509.MarshalPKIXPublicKey(cert.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("hostid: SPKI: %w", err)
	}
	return &Identity{
		Cert:        cert,
		Key:         key,
		SPKI:        spki,
		Fingerprint: Fingerprint(spki),
	}, nil
}

// SignBinding firma el vínculo de la clave de transporte con esta identidad.
// Devuelve el algoritmo (para anunciarlo), la firma y los bytes firmados.
func (id *Identity) SignBinding(transportSPKI []byte, at time.Time) (string, []byte, []byte, error) {
	payload := BindingPayload(transportSPKI, id.SPKI, at)

	switch key := id.Key.(type) {
	case *ecdsa.PrivateKey:
		hash := sha256.Sum256(payload)
		sig, err := ecdsa.SignASN1(rand.Reader, key, hash[:])
		if err != nil {
			return "", nil, nil, fmt.Errorf("hostid: firmar vínculo: %w", err)
		}
		return AlgECDSAP256, sig, payload, nil
	case *rsa.PrivateKey:
		hash := sha256.Sum256(payload)
		sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, hash[:])
		if err != nil {
			return "", nil, nil, fmt.Errorf("hostid: firmar vínculo: %w", err)
		}
		return AlgRSAPKCS1, sig, payload, nil
	default:
		return "", nil, nil, fmt.Errorf("hostid: clave de identidad de tipo no soportado (%T)", id.Key)
	}
}

// VerifyBinding comprueba un vínculo con la clave pública del certificado del
// host. Es lo que ejecuta el cliente (y wpfe-sign doctor) antes de confiar.
func VerifyBinding(hostPub crypto.PublicKey, payload, sig []byte) error {
	switch key := hostPub.(type) {
	case *ecdsa.PublicKey:
		hash := sha256.Sum256(payload)
		if !ecdsa.VerifyASN1(key, hash[:], sig) {
			return ErrVerify
		}
		return nil
	case *rsa.PublicKey:
		hash := sha256.Sum256(payload)
		if err := rsa.VerifyPKCS1v15(key, crypto.SHA256, hash[:], sig); err != nil {
			return ErrVerify
		}
		return nil
	default:
		return fmt.Errorf("%w: clave pública de tipo no soportado (%T)", ErrVerify, hostPub)
	}
}

// VerifyBindingPEM es VerifyBinding a partir del PEM del certificado del host
// (el que devuelve /v1/transport-key en el campo host_cert).
func VerifyBindingPEM(hostCertPEM, payload, sig []byte) error {
	block, _ := pem.Decode(hostCertPEM)
	if block == nil {
		return fmt.Errorf("%w: host_cert no es PEM", ErrVerify)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return fmt.Errorf("%w: host_cert ilegible: %v", ErrVerify, err)
	}
	return VerifyBinding(cert.PublicKey, payload, sig)
}

// writePEM persiste un bloque PEM con permisos concretos (escritura atómica).
func writePEM(path, blockType string, der []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("hostid: crear %s: %w", dir, err)
	}
	data := pem.EncodeToMemory(&pem.Block{Type: blockType, Bytes: der})
	tmp, err := os.CreateTemp(dir, ".hostid-*")
	if err != nil {
		return fmt.Errorf("hostid: temporal: %w", err)
	}
	name := tmp.Name()
	defer func() { _ = os.Remove(name) }()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("hostid: escritura: %w", err)
	}
	if err := tmp.Chmod(mode); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("hostid: chmod: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("hostid: cierre: %w", err)
	}
	if err := os.Rename(name, path); err != nil {
		return fmt.Errorf("hostid: rename: %w", err)
	}
	return nil
}
