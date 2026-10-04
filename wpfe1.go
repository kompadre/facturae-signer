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
//
// Formato: magic(5) + key_len(4, big-endian) + clave AES envuelta (RSA-OAEP SHA-1)
//   - iv_len(4, big-endian) + iv + ciphertext+tag GCM(16).
func decryptWPFE1(blob []byte, key *rsa.PrivateKey) ([]byte, error) {
	if len(blob) < 9 || string(blob[:5]) != "WPFE1" {
		return nil, errWPFE1Format
	}
	if key == nil {
		return nil, errWPFE1Unwrap
	}

	off := 5
	keyLen := binary.BigEndian.Uint32(blob[off : off+4])
	off += 4
	if keyLen == 0 || uint64(off)+uint64(keyLen)+4 > uint64(len(blob)) {
		return nil, errWPFE1Format
	}
	wrapped := blob[off : off+int(keyLen)]
	off += int(keyLen)

	ivLen := binary.BigEndian.Uint32(blob[off : off+4])
	off += 4
	// Tras la IV debe quedar al menos el tag GCM (16 bytes).
	if ivLen == 0 || uint64(off)+uint64(ivLen)+16 > uint64(len(blob)) {
		return nil, errWPFE1Format
	}
	iv := blob[off : off+int(ivLen)]
	off += int(ivLen)

	rest := blob[off:]
	ct, tag := rest[:len(rest)-16], rest[len(rest)-16:]

	aesKey, err := rsa.DecryptOAEP(sha1.New(), rand.Reader, key, wrapped, nil)
	if err != nil {
		return nil, errWPFE1Unwrap
	}
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, fmt.Errorf("%w: clave AES inválida", errWPFE1Decrypt)
	}
	gcm, err := cipher.NewGCMWithNonceSize(block, int(ivLen))
	if err != nil {
		return nil, fmt.Errorf("%w: %v", errWPFE1Decrypt, err)
	}
	sealed := make([]byte, 0, len(ct)+len(tag))
	sealed = append(sealed, ct...)
	sealed = append(sealed, tag...)
	plain, err := gcm.Open(nil, iv, sealed, nil)
	if err != nil {
		return nil, errWPFE1Decrypt
	}
	return plain, nil
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
