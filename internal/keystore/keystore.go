// Package keystore custodia la clave de transporte del signer en modo
// persistente (VPS): se genera una vez y se guarda cifrada en disco.
//
// Esquema (defensa en profundidad; el porqué está en README-vps.md):
//
//	master = HKDF-SHA256(ikm  = machine_secret ‖ external_salt,
//	                     salt = provision_salt,
//	                     info = "facturae-signer/master/v1|" ‖ base64(host SPKI))
//	blob   = AES-256-GCM(master, nonce aleatorio) sobre la clave de transporte PKCS#8
//
// El SPKI de la identidad x509 del host viaja en la CABECERA (público): la
// rotación del certificado (Let's Encrypt, ~90 días) no rompe el keystore,
// porque al arrancar se detecta el cambio y se re-envuelve la MISMA clave de
// transporte con la SPKI nueva. En cambio, si el fichero se copia a otra
// máquina (o se re-imagena), el machine_secret cambia, el master no se
// deriva y el signer rehúsa firmar: ése es el efecto buscado.
//
// El external_salt (opcional, /etc/facturae-signer.salt 0400 root:root)
// cierra el hueco del clon byte-a-byte de un host en marcha: ese fichero
// tampoco forma parte del clon si vive fuera del volumen copiado… y si el
// clon incluye el disco entero, sigue sin poderse usar sin leerlo de ESTE
// host (ver README para la matriz honesta de propiedades).
package keystore

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const (
	magic   = "WPFEK1"
	version = 1
	// algAES256GCM: clave AES-256, GCM con nonce de 12 bytes (estándar).
	algAES256GCM = 1

	defaultMachineIDFile  = "/etc/machine-id"
	fallbackMachineIDFile = "/var/lib/dbus/machine-id"
	// DefaultSaltFile es el external salt por defecto (opcional si no existe;
	// obligatorio si WPFE_MASTER_SALT_FILE apunta expresamente a un sitio).
	DefaultSaltFile = "/etc/facturae-signer.salt"

	masterInfoLabel = "facturae-signer/master/v1|"

	saltLen  = 32
	nonceLen = 12
	keyBits  = 2048
)

var (
	// ErrFormat: el fichero no es un keystore WPFEK1 o sus campos no cuadran.
	ErrFormat = errors.New("keystore: formato WPFEK1 no reconocido")
	// ErrLocked: el master no abre el blob — machine secret u external salt
	// distintos (clon de disco, máquina nueva, salt extraviado).
	ErrLocked = errors.New("keystore: no se puede abrir en este host (machine secret o salt distintos: ¿clon, máquina nueva o /etc/facturae-signer.salt perdido?)")
	// ErrNoHostSPKI: falta la identidad x509 del host (no se puede derivar nada).
	ErrNoHostSPKI = errors.New("keystore: falta la SPKI de la identidad del host")
	// ErrNoMachineSecret: no hay machine_secret disponible en este host.
	ErrNoMachineSecret = errors.New("keystore: no hay machine secret (WPFE_MACHINE_ID o /etc/machine-id)")
)

// DefaultPath es la ubicación por defecto del keystore (WPFE_KEYSTORE la cambia).
func DefaultPath() string { return "/var/lib/facturae-signer/keystore.bin" }

// blob es la representación en disco del keystore (cabecera pública + blob cifrado).
type blob struct {
	version byte
	alg     byte
	spki    []byte // SPKI de la identidad del host al provisionar (o al re-envolver)
	salt    []byte // provision salt (32)
	nonce   []byte // GCM nonce (12)
	ct      []byte // AES-GCM(clave de transporte PKCS#8) + tag
}

func (b *blob) marshal() []byte {
	out := make([]byte, 0, 6+2+len(b.spki)+1+len(b.salt)+1+len(b.nonce)+len(b.ct))
	out = append(out, magic...)
	out = append(out, b.version, b.alg)
	out = append(out, u16(uint16(len(b.spki)))...)
	out = append(out, b.spki...)
	out = append(out, byte(len(b.salt)))
	out = append(out, b.salt...)
	out = append(out, byte(len(b.nonce)))
	out = append(out, b.nonce...)
	out = append(out, b.ct...)
	return out
}

func parseBlob(data []byte) (*blob, error) {
	if len(data) < 6+2+2+1+1 {
		return nil, ErrFormat
	}
	if string(data[:6]) != magic {
		return nil, ErrFormat
	}
	off := 6
	b := &blob{version: data[off], alg: data[off+1]}
	off += 2
	if b.version != version || b.alg != algAES256GCM {
		return nil, fmt.Errorf("%w: versión/alg no soportado (%d/%d)", ErrFormat, b.version, b.alg)
	}
	spkiLen := int(binary.BigEndian.Uint16(data[off : off+2]))
	off += 2
	if spkiLen == 0 || off+spkiLen+2 > len(data) {
		return nil, ErrFormat
	}
	b.spki = append([]byte(nil), data[off:off+spkiLen]...)
	off += spkiLen

	saltLen := int(data[off])
	off++
	if saltLen == 0 || off+saltLen+1 > len(data) {
		return nil, ErrFormat
	}
	b.salt = append([]byte(nil), data[off:off+saltLen]...)
	off += saltLen

	nonceLen := int(data[off])
	off++
	if nonceLen == 0 || off+nonceLen+16 > len(data) { // mínimo: tag GCM (16)
		return nil, ErrFormat
	}
	b.nonce = append([]byte(nil), data[off:off+nonceLen]...)
	off += nonceLen
	b.ct = append([]byte(nil), data[off:]...)
	return b, nil
}

func u16(v uint16) []byte {
	var b [2]byte
	binary.BigEndian.PutUint16(b[:], v)
	return b[:]
}

// MachineSecret devuelve el secreto de máquina y su procedencia (para los
// mensajes de error de doctor/init). Prioridad: WPFE_MACHINE_ID (literal,
// para tests y contenedores) → WPFE_MACHINE_ID_FILE → /etc/machine-id →
// /var/lib/dbus/machine-id.
func MachineSecret() ([]byte, string, error) {
	if v := os.Getenv("WPFE_MACHINE_ID"); v != "" {
		return []byte(v), "env:WPFE_MACHINE_ID", nil
	}
	path := os.Getenv("WPFE_MACHINE_ID_FILE")
	fallback := false
	if path == "" {
		path = defaultMachineIDFile
		fallback = true
	}
	data, err := os.ReadFile(path)
	if err != nil && fallback {
		path = fallbackMachineIDFile
		data, err = os.ReadFile(path)
	}
	if err != nil {
		return nil, path, fmt.Errorf("%w: %v", ErrNoMachineSecret, err)
	}
	secret := bytes.TrimSpace(data)
	if len(secret) == 0 {
		return nil, path, fmt.Errorf("%w: %s vacío", ErrNoMachineSecret, path)
	}
	return secret, path, nil
}

// externalSalt devuelve el segundo factor opcional. Tres estados:
//
//	WPFE_MASTER_SALT_FILE sin definir → /etc/facturae-signer.salt si existe
//	                                    (opcional: ausente = sin salt)
//	WPFE_MASTER_SALT_FILE = /ruta     → ese fichero es OBLIGATORIO
//	WPFE_MASTER_SALT_FILE = ""        → desactivado explícitamente
//
// Un salt opcional que aparece/desaparece cambia el master y deja el
// keystore inutilizable: por eso el modo estricto es opt-in por variable.
func externalSalt() ([]byte, string, error) {
	v, set := os.LookupEnv("WPFE_MASTER_SALT_FILE")
	if set && strings.TrimSpace(v) == "" {
		return nil, "desactivado (WPFE_MASTER_SALT_FILE vacío)", nil
	}
	path := DefaultSaltFile
	strict := false
	if set {
		path = v
		strict = true
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) && !strict {
			return nil, path + " (ausente, opcional)", nil
		}
		return nil, path, fmt.Errorf("keystore: no se pudo leer el salt externo %s: %w", path, err)
	}
	data = bytes.TrimSpace(data)
	if len(data) == 0 {
		if strict {
			return nil, path, fmt.Errorf("keystore: %s definido pero vacío", path)
		}
		return nil, path + " (vacío)", nil
	}
	return data, path, nil
}

// masterKey deriva la clave maestra con separación de dominio por etiqueta
// (info) y por el SPKI de la identidad del host.
func masterKey(machineSecret, salt, hostSPKI, external []byte) ([]byte, error) {
	if len(machineSecret) == 0 {
		return nil, ErrNoMachineSecret
	}
	if len(hostSPKI) == 0 {
		return nil, ErrNoHostSPKI
	}
	ikm := machineSecret
	if len(external) > 0 {
		ikm = append(append([]byte(nil), machineSecret...), external...)
	}
	info := masterInfoLabel + base64.RawStdEncoding.EncodeToString(hostSPKI)
	return deriveKey(salt, ikm, []byte(info), 32)
}

func seal(master, plaintext, spki, salt []byte) (*blob, error) {
	block, err := aes.NewCipher(master)
	if err != nil {
		return nil, fmt.Errorf("keystore: AES: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("keystore: GCM: %w", err)
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("keystore: nonce: %w", err)
	}
	return &blob{
		version: version,
		alg:     algAES256GCM,
		spki:    append([]byte(nil), spki...),
		salt:    append([]byte(nil), salt...),
		nonce:   nonce,
		ct:      gcm.Seal(nil, nonce, plaintext, nil),
	}, nil
}

func open(master []byte, b *blob) ([]byte, error) {
	block, err := aes.NewCipher(master)
	if err != nil {
		return nil, ErrLocked
	}
	gcm, err := cipher.NewGCMWithNonceSize(block, len(b.nonce))
	if err != nil {
		return nil, ErrLocked
	}
	plain, err := gcm.Open(nil, b.nonce, b.ct, nil)
	if err != nil {
		return nil, ErrLocked
	}
	return plain, nil
}

func parseTransportKey(der []byte) (*rsa.PrivateKey, error) {
	parsed, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, fmt.Errorf("keystore: clave de transporte ilegible: %w", err)
	}
	key, ok := parsed.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("keystore: la clave de transporte no es RSA")
	}
	return key, nil
}

// LoadOrCreate devuelve la clave de transporte viva en este host.
//
//   - No existe el keystore ⇒ se genera la pareja de transporte (RSA-2048)
//     y se guarda cifrada (0640, directorio 0700, escritura atómica).
//   - Existe ⇒ se abre con el master derivado aquí. Si el SPKI guardado no
//     coincide con el del host actual (rotación del certificado) se
//     RE-ENVUELVE la misma clave con la SPKI nueva y se persiste.
//
// Devuelve además si ha habido re-envoltura (para el log de arranque).
func LoadOrCreate(path string, hostSPKI []byte) (*rsa.PrivateKey, bool, error) {
	machineSecret, machineSource, err := MachineSecret()
	if err != nil {
		return nil, false, err
	}
	external, saltSource, err := externalSalt()
	if err != nil {
		return nil, false, err
	}
	_ = saltSource

	data, err := os.ReadFile(path)
	if err != nil {
		if !os.IsNotExist(err) {
			return nil, false, fmt.Errorf("keystore: lectura de %s: %w", path, err)
		}
		// Alta: primera ejecución.
		key, der, err := generateTransportKey()
		if err != nil {
			return nil, false, err
		}
		salt := make([]byte, saltLen)
		if _, err := rand.Read(salt); err != nil {
			return nil, false, fmt.Errorf("keystore: provision salt: %w", err)
		}
		master, err := masterKey(machineSecret, salt, hostSPKI, external)
		if err != nil {
			return nil, false, err
		}
		b, err := seal(master, der, hostSPKI, salt)
		if err != nil {
			return nil, false, err
		}
		if err := writeAtomic(path, b.marshal()); err != nil {
			return nil, false, err
		}
		return key, false, nil
	}

	b, err := parseBlob(data)
	if err != nil {
		return nil, false, err
	}
	master, err := masterKey(machineSecret, b.salt, b.spki, external)
	if err != nil {
		return nil, false, err
	}
	plain, err := open(master, b)
	if err != nil {
		return nil, false, fmt.Errorf("%w (machine=%s)", err, machineSource)
	}
	defer Zero(plain)

	key, err := parseTransportKey(plain)
	if err != nil {
		return nil, false, err
	}

	rewrapped := false
	if !bytes.Equal(b.spki, hostSPKI) {
		// Rotación de la identidad del host: la misma clave de transporte se
		// re-envuelve bajo el master derivado con la SPKI nueva.
		master, err := masterKey(machineSecret, b.salt, hostSPKI, external)
		if err != nil {
			return nil, false, err
		}
		nb, err := seal(master, plain, hostSPKI, b.salt)
		if err != nil {
			return nil, false, err
		}
		if err := writeAtomic(path, nb.marshal()); err != nil {
			return nil, false, fmt.Errorf("keystore: re-envoltura no persistida: %w", err)
		}
		rewrapped = true
	}
	return key, rewrapped, nil
}

func generateTransportKey() (*rsa.PrivateKey, []byte, error) {
	key, err := rsa.GenerateKey(rand.Reader, keyBits)
	if err != nil {
		return nil, nil, fmt.Errorf("keystore: generar clave de transporte: %w", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, nil, fmt.Errorf("keystore: serializar clave: %w", err)
	}
	return key, der, nil
}

// writeAtomic: escribe a un temporal en el mismo directorio y renombra, para
// no dejar un keystore a medias si el proceso muere en mitad del guardado.
func writeAtomic(path string, data []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("keystore: crear %s: %w", dir, err)
	}
	tmp, err := os.CreateTemp(dir, ".keystore-*")
	if err != nil {
		return fmt.Errorf("keystore: temporal: %w", err)
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }()

	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("keystore: escritura: %w", err)
	}
	if err := tmp.Chmod(0o640); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("keystore: chmod: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("keystore: cierre: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("keystore: rename: %w", err)
	}
	return nil
}

// Zero limpia un buffer sensible (la clave de transporte en claro y el texto
// derivado). Go no permite limpiar strings, por eso la cadena de trabajo son
// siempre []byte: quien decodifique el JSON del envelope debe hacerlo sobre
// []byte y pasar por aquí (ver el contrato en envelope.go).
func Zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
