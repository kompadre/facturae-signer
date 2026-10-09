package keystore

import (
	"bytes"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// Vectores RFC 5869 (SHA-256), verificados además contra una implementación
// independiente (hmac/sha256 de la biblioteca estándar de Python) para no
// memorizarlos mal.
func TestHKDFRFC5869Vectors(t *testing.T) {
	// Test Case 1: IKM=0x0b×22, salt=0x00..0x0c, info=0xf0..0xf9, L=42
	ikm := bytes.Repeat([]byte{0x0b}, 22)
	salt := make([]byte, 13)
	for i := range salt {
		salt[i] = byte(i)
	}
	info := make([]byte, 10)
	for i := range info {
		info[i] = byte(0xf0 + i)
	}

	prk := hkdfExtract(salt, ikm)
	if got, want := hex.EncodeToString(prk), "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5"; got != want {
		t.Fatalf("PRK = %s, want %s", got, want)
	}
	okm, err := hkdfExpand(prk, info, 42)
	if err != nil {
		t.Fatalf("expand: %v", err)
	}
	if got, want := hex.EncodeToString(okm), "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"; got != want {
		t.Fatalf("OKM = %s, want %s", got, want)
	}

	// Test Case 3: salt e info vacíos.
	prk3 := hkdfExtract(nil, ikm)
	if got, want := hex.EncodeToString(prk3), "19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04"; got != want {
		t.Fatalf("TC3 PRK = %s, want %s", got, want)
	}
	okm3, err := hkdfExpand(prk3, nil, 42)
	if err != nil {
		t.Fatalf("TC3 expand: %v", err)
	}
	if got, want := hex.EncodeToString(okm3), "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8"; got != want {
		t.Fatalf("TC3 OKM = %s, want %s", got, want)
	}
}

// Cada entrada de la derivación cambia el master (separación de dominio).
func TestMasterKeyIsDomainSeparated(t *testing.T) {
	secret := []byte("machine-a")
	salt := bytes.Repeat([]byte{0x11}, saltLen)
	spki := []byte("spki-host")
	external := []byte("pepper")

	base, err := masterKey(secret, salt, spki, nil)
	if err != nil {
		t.Fatalf("masterKey: %v", err)
	}

	cases := map[string]func() ([]byte, error){
		"otro machine secret": func() ([]byte, error) { return masterKey([]byte("machine-b"), salt, spki, nil) },
		"otro salt":           func() ([]byte, error) { return masterKey(secret, bytes.Repeat([]byte{0x22}, saltLen), spki, nil) },
		"otra SPKI":           func() ([]byte, error) { return masterKey(secret, salt, []byte("spki-otro"), nil) },
		"con external salt":   func() ([]byte, error) { return masterKey(secret, salt, spki, external) },
	}
	for name, fn := range cases {
		got, err := fn()
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if bytes.Equal(got, base) {
			t.Errorf("%s: el master no cambió (la derivación no está separada por dominio)", name)
		}
	}
}

func TestSealOpenRoundtrip(t *testing.T) {
	master := bytes.Repeat([]byte{0x42}, 32)
	plain := []byte("clave de transporte en claro")
	salt := bytes.Repeat([]byte{0x11}, saltLen)

	b, err := seal(master, plain, []byte("spki"), salt)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	got, err := open(master, b)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if !bytes.Equal(got, plain) {
		t.Fatalf("roundtrip = %q, want %q", got, plain)
	}

	// El blob cifrado no contiene el texto original.
	if bytes.Contains(b.marshal(), plain) {
		t.Fatal("el texto original aparece sin cifrar en el blob")
	}
	// Un master distinto no abre nada.
	if _, err := open(bytes.Repeat([]byte{0x43}, 32), b); !errors.Is(err, ErrLocked) {
		t.Fatalf("master equivocado: err = %v, want ErrLocked", err)
	}
}

func TestLoadOrCreateGeneratesOnceThenReuses(t *testing.T) {
	t.Setenv("WPFE_MACHINE_ID", "machine-alpha")
	t.Setenv("WPFE_MASTER_SALT_FILE", "") // sin salt: comportamiento por defecto

	path := filepath.Join(t.TempDir(), "data", "keystore.bin")
	spki := []byte("spki-del-host")

	k1, rewrapped, err := LoadOrCreate(path, spki)
	if err != nil {
		t.Fatalf("alta: %v", err)
	}
	if rewrapped {
		t.Error("el alta no debe re-envolver")
	}

	k2, rewrapped, err := LoadOrCreate(path, spki)
	if err != nil {
		t.Fatalf("segunda carga: %v", err)
	}
	if rewrapped {
		t.Error("sin cambio de SPKI no debe haber re-envoltura")
	}
	if k1.N.Cmp(k2.N) != 0 || k1.E != k2.E {
		t.Fatal("la clave de transporte cambió entre arranques")
	}
}

// Es la prueba del ciclo Let's Encrypt: el SPKI del host rota y el keystore
// debe re-envolvérselo SIN rotar la clave de transporte (si no, cada 90 días
// habría que volver a subir el certificado en WordPress).
func TestSPKIRotationRewrapsKeepingTransportKey(t *testing.T) {
	t.Setenv("WPFE_MACHINE_ID", "machine-alpha")
	t.Setenv("WPFE_MASTER_SALT_FILE", "")

	path := filepath.Join(t.TempDir(), "data", "keystore.bin")

	k1, _, err := LoadOrCreate(path, []byte("spki-antes-de-renewal"))
	if err != nil {
		t.Fatalf("alta: %v", err)
	}

	k2, rewrapped, err := LoadOrCreate(path, []byte("spki-despues-de-renewal"))
	if err != nil {
		t.Fatalf("carga tras rotación: %v", err)
	}
	if !rewrapped {
		t.Fatal("con un SPKI nuevo debe re-envolverse y avisar")
	}
	if k1.N.Cmp(k2.N) != 0 || k1.E != k2.E {
		t.Fatal("la rotación del certificado rotó la clave de transporte (rompe a los clientes)")
	}

	// Y la re-envoltura ya persistida abre a la primera con la SPKI nueva.
	k3, rewrapped, err := LoadOrCreate(path, []byte("spki-despues-de-renewal"))
	if err != nil {
		t.Fatalf("carga tras re-envoltura: %v", err)
	}
	if rewrapped {
		t.Error("segunda carga con la SPKI ya nueva no debe re-envolver otra vez")
	}
	if k1.N.Cmp(k3.N) != 0 {
		t.Fatal("la clave de transporte cambió tras la re-envoltura")
	}
}

// Clon/máquina nueva: el machine secret cambia y el keystore rehúsa abrirse.
func TestDifferentMachineSecretRefusesToUnlock(t *testing.T) {
	t.Setenv("WPFE_MASTER_SALT_FILE", "")
	path := filepath.Join(t.TempDir(), "data", "keystore.bin")

	t.Setenv("WPFE_MACHINE_ID", "maquina-original")
	if _, _, err := LoadOrCreate(path, []byte("spki")); err != nil {
		t.Fatalf("alta: %v", err)
	}

	t.Setenv("WPFE_MACHINE_ID", "maquina-clonada")
	_, _, err := LoadOrCreate(path, []byte("spki"))
	if !errors.Is(err, ErrLocked) {
		t.Fatalf("clon: err = %v, want ErrLocked", err)
	}
}

// El salt externo es un segundo factor: sin él (o con otro) no se abre.
func TestExternalSaltIsSecondFactor(t *testing.T) {
	t.Setenv("WPFE_MACHINE_ID", "machine-alpha")
	dir := t.TempDir()
	saltPath := filepath.Join(dir, "facturae-signer.salt")
	if err := os.WriteFile(saltPath, []byte("pepper-uno"), 0o400); err != nil {
		t.Fatalf("escribir salt: %v", err)
	}
	path := filepath.Join(dir, "data", "keystore.bin")

	t.Setenv("WPFE_MASTER_SALT_FILE", saltPath)
	if _, _, err := LoadOrCreate(path, []byte("spki")); err != nil {
		t.Fatalf("alta con salt: %v", err)
	}

	// Mismo salt: abre.
	if _, _, err := LoadOrCreate(path, []byte("spki")); err != nil {
		t.Fatalf("carga con el mismo salt: %v", err)
	}

	// Salt distinto: no abre. Con el fichero en 0400 el write directo da
	// EACCES: se abre, se reescribe y se vuelve a dejar de sólo lectura.
	if err := os.Chmod(saltPath, 0o600); err != nil {
		t.Fatalf("chmod salt: %v", err)
	}
	if err := os.WriteFile(saltPath, []byte("pepper-dos"), 0o400); err != nil {
		t.Fatalf("reescribir salt: %v", err)
	}
	if err := os.Chmod(saltPath, 0o400); err != nil {
		t.Fatalf("chmod salt 0400: %v", err)
	}
	if _, _, err := LoadOrCreate(path, []byte("spki")); !errors.Is(err, ErrLocked) {
		t.Fatalf("salt cambiado: err = %v, want ErrLocked", err)
	}

	// Salt obligatorio que desaparece: error claro, no ErrLocked silencioso.
	if err := os.Remove(saltPath); err != nil {
		t.Fatalf("borrar salt: %v", err)
	}
	if _, _, err := LoadOrCreate(path, []byte("spki")); err == nil || errors.Is(err, ErrLocked) {
		t.Fatalf("salt desaparecido: err = %v, want error explícito de lectura", err)
	}

	// WPFE_MASTER_SALT_FILE vacío ⇒ desactivado explícitamente.
	t.Setenv("WPFE_MASTER_SALT_FILE", "")
	if _, _, err := LoadOrCreate(path, []byte("spki")); err == nil {
		t.Fatal("sin salt y con otro master no debe abrirse")
	}
}

// Permisos de escritura: 0640 el keystore, 0700 su directorio.
func TestFilePermissions(t *testing.T) {
	t.Setenv("WPFE_MACHINE_ID", "machine-alpha")
	t.Setenv("WPFE_MASTER_SALT_FILE", "")

	path := filepath.Join(t.TempDir(), "data", "keystore.bin")
	if _, _, err := LoadOrCreate(path, []byte("spki")); err != nil {
		t.Fatalf("alta: %v", err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat keystore: %v", err)
	}
	if got := info.Mode().Perm(); got != 0o640 {
		t.Errorf("permisos del keystore = %04o, want 0640", got)
	}
	dirInfo, err := os.Stat(filepath.Dir(path))
	if err != nil {
		t.Fatalf("stat dir: %v", err)
	}
	if got := dirInfo.Mode().Perm(); got != 0o700 {
		t.Errorf("permisos del directorio = %04o, want 0700", got)
	}
}

func TestParseBlobRejectsGarbage(t *testing.T) {
	if _, err := parseBlob([]byte("esto no es un keystore")); !errors.Is(err, ErrFormat) {
		t.Fatalf("err = %v, want ErrFormat", err)
	}
	if _, err := parseBlob(nil); !errors.Is(err, ErrFormat) {
		t.Fatalf("nil: err = %v, want ErrFormat", err)
	}
}
