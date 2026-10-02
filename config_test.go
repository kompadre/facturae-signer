package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func pemPKCS8(t *testing.T, key any) []byte {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("marshal pkcs8: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
}

func TestLoadConfigInlinePEM(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	pemBytes := pemPKCS8(t, key)

	t.Setenv("WPFE_PRIVATE_KEY", string(pemBytes))
	t.Setenv("PKCS12_PASSWORD", "secreta")

	cfg, err := loadConfigFromEnv()
	if err != nil {
		t.Fatalf("loadConfigFromEnv: %v", err)
	}
	if cfg.password != "secreta" {
		t.Errorf("password = %q", cfg.password)
	}
	if cfg.privateKey.N.Cmp(key.N) != 0 {
		t.Error("la clave cargada no coincide con la generada")
	}
}

func TestLoadConfigFromFilePath(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	pkcs1 := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})
	path := filepath.Join(t.TempDir(), "key.pem")
	if err := os.WriteFile(path, pkcs1, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	t.Setenv("WPFE_PRIVATE_KEY", path)
	t.Setenv("PKCS12_PASSWORD", "")

	cfg, err := loadConfigFromEnv()
	if err != nil {
		t.Fatalf("loadConfigFromEnv: %v", err)
	}
	if cfg.password != "" {
		t.Errorf("password = %q, se esperaba vacía", cfg.password)
	}
	if cfg.privateKey.N.Cmp(key.N) != 0 {
		t.Error("la clave cargada no coincide con la del fichero")
	}
}

func TestLoadConfigMissingEnv(t *testing.T) {
	t.Setenv("WPFE_PRIVATE_KEY", "")
	if _, err := loadConfigFromEnv(); err == nil {
		t.Fatal("se esperaba error sin WPFE_PRIVATE_KEY")
	}
}

func TestLoadConfigPasswordFromFile(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	t.Setenv("WPFE_PRIVATE_KEY", string(pemPKCS8(t, key)))
	t.Setenv("PKCS12_PASSWORD", "")
	t.Setenv("PKCS12_PASSWORD_FILE", "")

	pwPath := filepath.Join(t.TempDir(), "pw")
	if err := os.WriteFile(pwPath, []byte("desde-fichero\n"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	t.Setenv("PKCS12_PASSWORD_FILE", pwPath)

	cfg, err := loadConfigFromEnv()
	if err != nil {
		t.Fatalf("loadConfigFromEnv: %v", err)
	}
	if cfg.password != "desde-fichero" {
		t.Errorf("password = %q, se esperaba \"desde-fichero\"", cfg.password)
	}
}

func TestLoadConfigRejectsGarbage(t *testing.T) {
	t.Setenv("WPFE_PRIVATE_KEY", "esto no es un PEM")
	if _, err := loadConfigFromEnv(); err == nil {
		t.Fatal("se esperaba error con contenido basura")
	}
}

func TestLoadConfigRejectsNonRSAKey(t *testing.T) {
	ecKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	t.Setenv("WPFE_PRIVATE_KEY", string(pemPKCS8(t, ecKey)))

	_, err := loadConfigFromEnv()
	if err == nil || !strings.Contains(err.Error(), "RSA") {
		t.Errorf("se esperaba error de clave no-RSA, se obtuvo %v", err)
	}
}

func TestParseRSAPrivateKeyPEMRejectsEncryptedBlock(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	pkcs1 := x509.MarshalPKCS1PrivateKey(key)
	block := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: pkcs1,
		Headers: map[string]string{
			"Proc-Type": "4,ENCRYPTED",
			"DEK-Info":  "DES-CBC,0000000000000000",
		},
	}
	data := pem.EncodeToMemory(block)
	if _, err := parseRSAPrivateKeyPEM(data); err == nil {
		t.Fatal("se esperaba rechazo de clave cifrada")
	}
}
