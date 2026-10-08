package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1" //nolint:gosec // el contrato con WordPress usa OAEP con SHA-1 (por defecto en OpenSSL/PHP)
	"encoding/binary"
	"errors"
	"fmt"
)

var (
	errWPFE1Format  = errors.New("certificate: formato WPFE1 no reconocido")
	errWPFE1Unwrap  = errors.New("certificate: no se pudo descifrar la clave con la clave privada configurada")
	errWPFE1Decrypt = errors.New("certificate: descifrado AES-GCM fallido")
)

// decryptWPFE1 descifra el blob producido por WPFacturaE::encrypt_with_public_key.
func decryptWPFE1(blob []byte, key *rsa.PrivateKey) ([]byte, error) {
	plain, _, err := openWPFE1(blob, key)
	return plain, err
}

// openWPFE1 es decryptWPFE1 devolviendo además la clave AES efímera: sólo se
// usa para sellar la respuesta con la misma clave (WPFE_SEAL_RESPONSES=1),
// de modo que el cliente no necesita pareja propia. Formato del blob:
//
//	magic(5) + key_len(4, BE) + clave AES envuelta (RSA-OAEP SHA-1)
//	+ iv_len(4, BE) + iv + ciphertext+tag GCM(16)
func openWPFE1(blob []byte, key *rsa.PrivateKey) ([]byte, []byte, error) {
	if len(blob) < 9 || string(blob[:5]) != "WPFE1" {
		return nil, nil, errWPFE1Format
	}
	if key == nil {
		return nil, nil, errWPFE1Unwrap
	}

	off := 5
	keyLen := binary.BigEndian.Uint32(blob[off : off+4])
	off += 4
	if keyLen == 0 || uint64(off)+uint64(keyLen)+4 > uint64(len(blob)) {
		return nil, nil, errWPFE1Format
	}
	wrapped := blob[off : off+int(keyLen)]
	off += int(keyLen)

	ivLen := binary.BigEndian.Uint32(blob[off : off+4])
	off += 4
	// Tras la IV debe quedar al menos el tag GCM (16 bytes).
	if ivLen == 0 || uint64(off)+uint64(ivLen)+16 > uint64(len(blob)) {
		return nil, nil, errWPFE1Format
	}
	iv := blob[off : off+int(ivLen)]
	off += int(ivLen)

	rest := blob[off:]
	ct, tag := rest[:len(rest)-16], rest[len(rest)-16:]

	aesKey, err := rsa.DecryptOAEP(sha1.New(), rand.Reader, key, wrapped, nil)
	if err != nil {
		return nil, nil, errWPFE1Unwrap
	}
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: clave AES inválida", errWPFE1Decrypt)
	}
	gcm, err := cipher.NewGCMWithNonceSize(block, int(ivLen))
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %v", errWPFE1Decrypt, err)
	}
	sealed := make([]byte, 0, len(ct)+len(tag))
	sealed = append(sealed, ct...)
	sealed = append(sealed, tag...)
	plain, err := gcm.Open(nil, iv, sealed, nil)
	if err != nil {
		return nil, nil, errWPFE1Decrypt
	}
	return plain, aesKey, nil
}

// sealWPFE1 cifra plaintext con una clave AES efímera envuelta a la pública
// de transporte: es el exacto inverso de openWPFE1 y el mismo formato que
// produce PHP (WPFacturaE::encrypt_with_public_key), así que el lado
// WordPress lo abre con decrypt_with_private_key sin cambios.
func sealWPFE1(plaintext []byte, pub *rsa.PublicKey) ([]byte, error) {
	aesKey := make([]byte, 32)
	if _, err := rand.Read(aesKey); err != nil {
		return nil, fmt.Errorf("wpfe1: clave AES: %w", err)
	}
	out, err := sealWPFE1WithKey(plaintext, aesKey, pub)
	zeroWPFE(aesKey)
	return out, err
}

// sealWPFE1WithKey sella con una clave AES concreta (la del request, cuando
// la respuesta va cifrada con la misma clave que ya conoce el cliente).
func sealWPFE1WithKey(plaintext, aesKey []byte, pub *rsa.PublicKey) ([]byte, error) {
	if len(aesKey) != 32 {
		return nil, fmt.Errorf("%w: clave AES de %d bytes", errWPFE1Format, len(aesKey))
	}
	iv := make([]byte, 12)
	if _, err := rand.Read(iv); err != nil {
		return nil, fmt.Errorf("wpfe1: iv: %w", err)
	}
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", errWPFE1Decrypt, err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", errWPFE1Decrypt, err)
	}
	ct := gcm.Seal(nil, iv, plaintext, nil)

	wrapped, errW := rsa.EncryptOAEP(sha1.New(), rand.Reader, pub, aesKey, nil)
	if errW != nil {
		return nil, fmt.Errorf("%w: envolver clave AES: %v", errWPFE1Unwrap, errW)
	}

	out := make([]byte, 0, 5+4+len(wrapped)+4+len(iv)+len(ct))
	out = append(out, "WPFE1"...)
	out = append(out, u32be(uint32(len(wrapped)))...)
	out = append(out, wrapped...)
	out = append(out, u32be(uint32(len(iv)))...)
	out = append(out, iv...)
	out = append(out, ct...)
	return out, nil
}

func u32be(v uint32) []byte {
	return []byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)}
}

// zeroWPFE limpia un buffer sensible (clave AES en claro).
func zeroWPFE(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// wpfeDecryptError añade la pista de rotación cuando la clave de transporte
// es la generada por el propio signer (modo generate): un reinicio del
// enclave rota la clave y los blobs antiguos ya no se abren — solución:
// volver a subir el certificado en Ajustes (la pública cambió).
func wpfeDecryptError(err error) error {
	if err == nil {
		return nil
	}
	if transportKeyGenerated {
		return fmt.Errorf("%w — ¿rotación de la clave? Vuelve a subir el certificado en Ajustes", err)
	}
	return err
}
