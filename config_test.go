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
	"reflect"
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

	cfg, err := loadConfigFromEnv()
	if err != nil {
		t.Fatalf("loadConfigFromEnv: %v", err)
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

	cfg, err := loadConfigFromEnv()
	if err != nil {
		t.Fatalf("loadConfigFromEnv: %v", err)
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

func TestLoadConfigIgnoresLegacyPasswordEnv(t *testing.T) {
	// El signer ya no tiene ninguna contraseña de PKCS#12: aunque queden
	// variables de entorno antigüas, la configuración no las recoge.
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	t.Setenv("WPFE_PRIVATE_KEY", string(pemPKCS8(t, key)))
	t.Setenv("PKCS12_PASSWORD", "secreta")
	t.Setenv("PKCS12_PASSWORD_FILE", "/no/existe")

	cfg, err := loadConfigFromEnv()
	if err != nil {
		t.Fatalf("loadConfigFromEnv: %v", err)
	}
	if cfg.privateKey == nil {
		t.Fatal("privateKey = nil")
	}
	if !reflect.DeepEqual(cfg, &signerConfig{privateKey: cfg.privateKey}) {
		t.Errorf("config inesperada: %+v", cfg)
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
