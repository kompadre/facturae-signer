package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// captureStdout redirige os.Stdout a un fichero temporal mientras corre fn
// (evita el bloqueo de una tubería si la salida crece).
func captureStdout(t *testing.T, fn func() int) (int, string) {
	t.Helper()
	file, err := os.CreateTemp(t.TempDir(), "stdout-")
	if err != nil {
		t.Fatalf("temp stdout: %v", err)
	}
	old := os.Stdout
	os.Stdout = file
	defer func() { os.Stdout = old }()

	code := fn()

	os.Stdout = old
	if err := file.Close(); err != nil {
		t.Fatalf("cerrar stdout: %v", err)
	}
	data, err := os.ReadFile(file.Name())
	if err != nil {
		t.Fatalf("leer stdout: %v", err)
	}
	return code, string(data)
}

// withStdin alimenta stdin del proceso con $data (la lectura llega a EOF).
func withStdin(t *testing.T, data string) {
	t.Helper()
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe stdin: %v", err)
	}
	if _, err := io.WriteString(writer, data); err != nil {
		t.Fatalf("escribir stdin: %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("cerrar stdin: %v", err)
	}
	old := os.Stdin
	os.Stdin = reader
	t.Cleanup(func() { os.Stdin = old; _ = reader.Close() })
}

func stashConfig(t *testing.T) {
	t.Helper()
	prev := activeConfig
	t.Cleanup(func() { activeConfig = prev })
}

// envMode instala el modo histórico (clave PEM por variable de entorno).
func envMode(t *testing.T) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generar clave: %v", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("serializar clave: %v", err)
	}
	t.Setenv("WPFE_KEY_MODE", "env")
	t.Setenv("WPFE_PRIVATE_KEY", string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})))
}

// persistentMode instala el modo VPS (keystore + identidad de host) en un
// directorio temporal con un machine secret conocido.
func persistentMode(t *testing.T, machine string) {
	t.Helper()
	t.Setenv("WPFE_KEY_MODE", "persistent")
	t.Setenv("WPFE_DATA_DIR", t.TempDir())
	t.Setenv("WPFE_MACHINE_ID", machine)
	t.Setenv("WPFE_MASTER_SALT_FILE", "")
	t.Setenv("WPFE_KEYSTORE", "")
	t.Setenv("WPFE_HOST_CERT", "")
	t.Setenv("WPFE_HOST_KEY", "")
}

func TestCLIUsageWithoutArguments(t *testing.T) {
	if code := cliRun(nil); code != exitInput {
		t.Fatalf("sin argumentos: código = %d, want %d", code, exitInput)
	}
	if code := cliRun([]string{"frobnicate"}); code != exitInput {
		t.Fatalf("comando desconocido: código = %d, want %d", code, exitInput)
	}
}

func TestCLIInitCreatesKeystoreAndPrintsFingerprint(t *testing.T) {
	stashConfig(t)
	persistentMode(t, "maquina-init")

	code, out := captureStdout(t, func() int { return cliRun([]string{"init"}) })
	if code != exitOK {
		t.Fatalf("init: código = %d (salida: %s)", code, out)
	}
	for _, want := range []string{"modo: persistent", "host_fingerprint: sha256:", "keystore: ", "salt_externo: desactivado", "transport_key_id: sha256:"} {
		if !strings.Contains(out, want) {
			t.Errorf("init no imprime %q; salida:\n%s", want, out)
		}
	}

	// Idempotente: segunda pasada no rota nada (misma huella).
	_, out2 := captureStdout(t, func() int { return cliRun([]string{"init"}) })
	if !strings.Contains(out2, "host_fingerprint: sha256:") {
		t.Errorf("segundo init sin huella:\n%s", out2)
	}
	fp1 := strings.SplitN(out, "host_fingerprint: ", 2)[1]
	fp2 := strings.SplitN(out2, "host_fingerprint: ", 2)[1]
	if strings.SplitN(fp1, "\n", 2)[0] != strings.SplitN(fp2, "\n", 2)[0] {
		t.Error("el segundo init rotó la identidad del host")
	}
}

func TestCLIDoctorRefusesForeignMachine(t *testing.T) {
	stashConfig(t)
	persistentMode(t, "maquina-original")

	if code := cliRun([]string{"doctor"}); code != exitOK {
		t.Fatalf("doctor en su máquina: código = %d, want 0", code)
	}

	// Clon: mismo keystore, otro machine secret → no se puede firmar.
	t.Setenv("WPFE_MACHINE_ID", "maquina-clonada")
	if code := cliRun([]string{"doctor"}); code != exitKey {
		t.Fatalf("doctor en clon: código = %d, want %d", code, exitKey)
	}
}

func TestCLIPubkeyPEMInEnvMode(t *testing.T) {
	stashConfig(t)
	envMode(t)

	code, out := captureStdout(t, func() int { return cliRun([]string{"pubkey"}) })
	if code != exitOK {
		t.Fatalf("pubkey: código = %d", code)
	}
	if !strings.Contains(out, "-----BEGIN PUBLIC KEY-----") {
		t.Fatalf("pubkey no imprime PEM:\n%s", out)
	}
}

func TestCLIPubkeyJSONInPersistentMode(t *testing.T) {
	stashConfig(t)
	persistentMode(t, "maquina-pubkey")

	code, out := captureStdout(t, func() int { return cliRun([]string{"pubkey", "--json"}) })
	if code != exitOK {
		t.Fatalf("pubkey --json: código = %d", code)
	}

	var doc struct {
		TransportKey    string `json:"transport_key"`
		HostPublicKey   string `json:"host_public_key"`
		HostFingerprint string `json:"host_fingerprint"`
		Binding         string `json:"binding"`
		BindingAlg      string `json:"binding_alg"`
		IssuedAt        string `json:"issued_at"`
	}
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatalf("stdout no es JSON: %v\n%s", err, out)
	}
	if doc.TransportKey == "" || doc.HostPublicKey == "" || doc.Binding == "" || doc.BindingAlg == "" {
		t.Fatalf("documento de vínculo incompleto: %+v", doc)
	}
	if !strings.HasPrefix(doc.HostFingerprint, "sha256:") {
		t.Errorf("host_fingerprint = %q", doc.HostFingerprint)
	}
}

// El pipeline completo del CLI: stdin → sellado → envoltorio → handler →
// stdout, con la traducción de códigos que usará PHP.
func TestCLIRequestSignPipeline(t *testing.T) {
	stashConfig(t)
	envMode(t)
	withStdin(t, `{"xml":"QUJD"}`) // sin certificate → 400

	code, out := captureStdout(t, func() int { return cliRun([]string{"sign"}) })
	if code != exitInput {
		t.Fatalf("sign sin certificate: código = %d, want %d (salida: %s)", code, exitInput, out)
	}
	if !strings.Contains(out, `"error"`) || !strings.Contains(out, "certificate") {
		t.Fatalf("el error no viaja como el endpoint:\n%s", out)
	}
}

// Sin clave utilizable el CLI no intenta nada y devuelve 3 (→ 503 en PHP).
func TestCLIRequestFailsWithUnusableKey(t *testing.T) {
	stashConfig(t)
	persistentMode(t, "maquina-una")
	if _, err := loadAndStore(t); err != nil {
		t.Fatalf("preparar keystore: %v", err)
	}

	t.Setenv("WPFE_MACHINE_ID", "maquina-dos")
	withStdin(t, `{"xml":"QUJD"}`)

	code, out := captureStdout(t, func() int { return cliRun([]string{"sign"}) })
	if code != exitKey {
		t.Fatalf("keystore bloqueado: código = %d, want %d", code, exitKey)
	}
	if !strings.Contains(out, `"error"`) {
		t.Fatalf("falta el JSON de error:\n%s", out)
	}
}

// loadAndStore crea el keystore en el modo ya configurado (helper de tests).
func loadAndStore(t *testing.T) (*signerConfig, error) {
	t.Helper()
	cfg, err := loadSignerConfig()
	if err == nil {
		activeConfig = cfg
	}
	return cfg, err
}

func TestExitCodeFor(t *testing.T) {
	cases := map[int]int{
		200: exitOK,
		201: exitOK,
		400: exitInput,
		503: exitKey,
		500: exitUpstream,
		502: exitUpstream,
		404: exitUpstream,
	}
	for status, want := range cases {
		if got := exitCodeFor(status); got != want {
			t.Errorf("exitCodeFor(%d) = %d, want %d", status, got, want)
		}
	}
}

// serve (sin LISTEN) fija el socket unix local; con LISTEN puesto lo respeta.
func TestCLIServeResolvesListenAddress(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "signer.sock")
	t.Setenv("LISTEN", "")
	t.Setenv("WPFE_SOCKET", sock)

	if got, want := serveListenAddr(), "unix:"+sock; got != want {
		t.Fatalf("serveListenAddr() = %q, want %q", got, want)
	}
	if got := os.Getenv("LISTEN"); got != "unix:"+sock {
		t.Fatalf("LISTEN = %q, want %q", got, "unix:"+sock)
	}

	// Con LISTEN explícito no se toca nada (un operador puede servir en TCP).
	t.Setenv("LISTEN", ":8080")
	if got := serveListenAddr(); got != ":8080" {
		t.Fatalf("serveListenAddr() con LISTEN = %q", got)
	}
}
