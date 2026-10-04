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

	cfg, err := loadSignerConfig()
	if err != nil {
		t.Fatalf("loadSignerConfig: %v", err)
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

	cfg, err := loadSignerConfig()
	if err != nil {
		t.Fatalf("loadSignerConfig: %v", err)
	}
	if cfg.privateKey.N.Cmp(key.N) != 0 {
		t.Error("la clave cargada no coincide con la del fichero")
	}
}

func TestLoadConfigMissingEnv(t *testing.T) {
	t.Setenv("WPFE_PRIVATE_KEY", "")
	if _, err := loadSignerConfig(); err == nil {
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

	cfg, err := loadSignerConfig()
	if err != nil {
		t.Fatalf("loadSignerConfig: %v", err)
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
	if _, err := loadSignerConfig(); err == nil {
		t.Fatal("se esperaba error con contenido basura")
	}
}

func TestLoadConfigRejectsNonRSAKey(t *testing.T) {
	ecKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	t.Setenv("WPFE_PRIVATE_KEY", string(pemPKCS8(t, ecKey)))

	_, err := loadSignerConfig()
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

func TestLoadSignerConfigGenerateMode(t *testing.T) {
	t.Setenv("WPFE_KEY_MODE", "generate")
	t.Setenv("WPFE_PRIVATE_KEY", "") // no debe mirarse en este modo

	cfg, err := loadSignerConfig()
	if err != nil {
		t.Fatalf("loadSignerConfig: %v", err)
	}
	if !cfg.generated || cfg.privateKey == nil {
		t.Fatalf("generated = %v, key = %v", cfg.generated, cfg.privateKey == nil)
	}
	if !transportKeyGenerated {
		t.Error("transportKeyGenerated debe ser true en modo generate")
	}
	t.Cleanup(func() { transportKeyGenerated = false })

	// La SPKI pública es utilizable por WordPress (RSA PKIX).
	pemStr, err := transportPublicKeyPEM(cfg.privateKey)
	if err != nil {
		t.Fatalf("transportPublicKeyPEM: %v", err)
	}
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil || block.Type != "PUBLIC KEY" {
		t.Fatalf("SPKI PEM inválido: %q", pemStr[:20])
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		t.Fatalf("ParsePKIXPublicKey: %v", err)
	}
	if _, ok := parsed.(*rsa.PublicKey); !ok {
		t.Fatal("la SPKI no es una clave RSA pública")
	}
	der, err := transportPublicKeyDER(cfg.privateKey)
	if err != nil || len(der) == 0 {
		t.Fatalf("transportPublicKeyDER: %v (%d)", err, len(der))
	}
	// El DER del attestation y el PEM servido deben ser el mismo material.
	if string(block.Bytes) != string(der) {
		t.Error("SPKI PEM y DER no coinciden")
	}
}

func TestLoadSignerConfigUnknownMode(t *testing.T) {
	t.Setenv("WPFE_KEY_MODE", "sgx")
	if _, err := loadSignerConfig(); err == nil {
		t.Fatal("se esperaba error con modo desconocido")
	}
}

func TestLoadSignerConfigEnvModeClearsGeneratedFlag(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	pkcs1 := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})
	t.Setenv("WPFE_KEY_MODE", "env")
	t.Setenv("WPFE_PRIVATE_KEY", string(pkcs1))

	cfg, err := loadSignerConfig()
	if err != nil {
		t.Fatalf("loadSignerConfig: %v", err)
	}
	if cfg.generated || transportKeyGenerated {
		t.Error("modo env no debe marcar generated")
	}
}
