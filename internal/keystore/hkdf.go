package keystore

import (
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"fmt"
)

// HKDF-SHA256 (RFC 5869) implementado aquí a mano para no añadir
// dependencias al árbol de build estático. Los tests lo validan contra los
// vectores oficiales del RFC 5869 (Test Case 1-4, SHA-256).

var errLength = errors.New("hkdf: longitud solicitada no soportada (máx 255*32)")

// hkdfExtract = HMAC-SHA256(salt, ikm).
func hkdfExtract(salt, ikm []byte) []byte {
	if len(salt) == 0 {
		salt = make([]byte, sha256.Size)
	}
	m := hmac.New(sha256.New, salt)
	m.Write(ikm) //nolint:errcheck // hmac.Hash.Write nunca falla
	return m.Sum(nil)
}

// hkdfExpand = T(1)..T(n) encadenados (RFC 5869 §2.3).
func hkdfExpand(prk, info []byte, length int) ([]byte, error) {
	if length > 255*sha256.Size {
		return nil, errLength
	}
	var (
		out     []byte
		t       []byte
		counter byte = 1
	)
	for len(out) < length {
		m := hmac.New(sha256.New, prk)
		m.Write(t)               //nolint:errcheck
		m.Write(info)            //nolint:errcheck
		m.Write([]byte{counter}) //nolint:errcheck
		t = m.Sum(nil)
		out = append(out, t...)
		counter++
	}
	return out[:length], nil
}

// deriveKey = HKDF-Extract + HKDF-Expand con la etiqueta de dominio pedida.
func deriveKey(salt, ikm, info []byte, length int) ([]byte, error) {
	if len(ikm) == 0 {
		return nil, fmt.Errorf("hkdf: ikm vacío")
	}
	return hkdfExpand(hkdfExtract(salt, ikm), info, length)
}
