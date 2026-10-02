package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1" //nolint:gosec // OAEP SHA-1, igual que PHP
	"encoding/binary"
	"errors"
	"testing"
)

// encryptWPFE1 construye un blob con el mismo formato que
// WPFacturaE::encrypt_with_public_key (para pruebas).
func encryptWPFE1(t *testing.T, plaintext []byte, pub *rsa.PublicKey) []byte {
	t.Helper()

	aesKey := make([]byte, 32)
	if _, err := rand.Read(aesKey); err != nil {
		t.Fatalf("aes key: %v", err)
	}
	iv := make([]byte, 12)
	if _, err := rand.Read(iv); err != nil {
		t.Fatalf("iv: %v", err)
	}
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		t.Fatalf("cipher: %v", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatalf("gcm: %v", err)
	}
	ct := gcm.Seal(nil, iv, plaintext, nil) // ciphertext||tag

	wrapped, err := rsa.EncryptOAEP(sha1.New(), rand.Reader, pub, aesKey, nil)
	if err != nil {
		t.Fatalf("oaep: %v", err)
	}

	out := []byte("WPFE1")
	out = binary.BigEndian.AppendUint32(out, uint32(len(wrapped)))
	out = append(out, wrapped...)
	out = binary.BigEndian.AppendUint32(out, uint32(len(iv)))
	out = append(out, iv...)
	out = append(out, ct...)
	return out
}

func TestWPFE1RoundTrip(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("clave: %v", err)
	}
	plaintext := make([]byte, 4096)
	if _, err := rand.Read(plaintext); err != nil {
		t.Fatalf("plaintext: %v", err)
	}

	blob := encryptWPFE1(t, plaintext, &key.PublicKey)
	got, err := decryptWPFE1(blob, key)
	if err != nil {
		t.Fatalf("decryptWPFE1: %v", err)
	}
	if string(got) != string(plaintext) {
		t.Error("el texto descifrado no coincide con el original")
	}
}

func TestWPFE1RejectsBadMagic(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	if _, err := decryptWPFE1([]byte("NOPE1abc"), key); !errors.Is(err, errWPFE1Format) {
		t.Errorf("err = %v, se esperaba errWPFE1Format", err)
	}
	if _, err := decryptWPFE1(nil, key); !errors.Is(err, errWPFE1Format) {
		t.Errorf("err = %v, se esperaba errWPFE1Format", err)
	}
}

func TestWPFE1RejectsTruncated(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	blob := encryptWPFE1(t, []byte("hola"), &key.PublicKey)

	// Truncar dentro de la clave envuelta.
	if _, err := decryptWPFE1(blob[:20], key); !errors.Is(err, errWPFE1Format) {
		t.Errorf("truncado corto: err = %v", err)
	}
	// Truncar tras la cabecera de la IV (sin tag GCM completo).
	if _, err := decryptWPFE1(blob[:len(blob)-8], key); !errors.Is(err, errWPFE1Format) {
		t.Errorf("truncado sin tag: err = %v", err)
	}
	// key_len = 0.
	bad := []byte("WPFE1")
	bad = binary.BigEndian.AppendUint32(bad, 0)
	if _, err := decryptWPFE1(bad, key); !errors.Is(err, errWPFE1Format) {
		t.Errorf("key_len 0: err = %v", err)
	}
}

func TestWPFE1RejectsWrongKey(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	other, _ := rsa.GenerateKey(rand.Reader, 2048)
	blob := encryptWPFE1(t, []byte("secreto"), &key.PublicKey)

	if _, err := decryptWPFE1(blob, other); !errors.Is(err, errWPFE1Unwrap) {
		t.Errorf("err = %v, se esperaba errWPFE1Unwrap", err)
	}
}

func TestWPFE1RejectsTamperedCiphertext(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	blob := encryptWPFE1(t, []byte("secreto"), &key.PublicKey)
	blob[len(blob)-1] ^= 0xff

	if _, err := decryptWPFE1(blob, key); !errors.Is(err, errWPFE1Decrypt) {
		t.Errorf("err = %v, se esperaba errWPFE1Decrypt", err)
	}
}
