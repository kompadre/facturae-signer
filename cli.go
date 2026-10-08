package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"

	"facturae-signer/internal/keystore"
)

// wpfe-sign: el MISMO binario del signer con subcomandos.
//
// Sin argumentos → servidor (TCP/vsock/unix según LISTEN). Con argumentos →
// CLI, para que WordPress pueda firmar en el mismo host sin abrir un puerto
// (fallback cuando no hay socket) y para aprovisionar/diagnosticar:
//
//	wpfe-sign serve                 sirve por socket (LISTEN/WPFE_SOCKET)
//	wpfe-sign init                  alta de keystore + identidad de host
//	wpfe-sign doctor                diagnóstico (sale distinto de 0 si no se puede firmar)
//	wpfe-sign pubkey [--json]       clave pública (PEM / documento de vínculo)
//	wpfe-sign sign|pdf|verifactu-alta|verifactu-consulta < body.json
//
// Los comandos de petición leen el JSON por stdin y escriben la respuesta
// por stdout con la MISMA forma que el endpoint HTTP (incluido el envoltorio
// WPFE1: el cuerpo se sella aquí dentro, en el propio proceso). Códigos de
// salida, que el plugin traduce a códigos HTTP:
//
//	0 → 200   ok
//	2 → 400   petición inválida
//	3 → 503   clave/keystore no disponible en este host
//	4 → resto  error del handler o del upstream (AEAT)
const (
	exitOK       = 0
	exitInput    = 2
	exitKey      = 3
	exitUpstream = 4
)

func cliUsage(w io.Writer) {
	fmt.Fprint(w, `wpfe-sign — firma Facturae/VeriFactu en local

  wpfe-sign serve                 escucha en el socket unix (LISTEN/WPFE_SOCKET)
  wpfe-sign init                  alta de keystore + identidad de host
  wpfe-sign doctor                diagnóstico (0 = se puede firmar aquí)
  wpfe-sign pubkey [--json]       clave pública (PEM o documento de vínculo)
  wpfe-sign <sign|pdf|verifactu-alta|verifactu-consulta> < body.json

Los comandos de petición leen JSON por stdin y escriben la respuesta por
stdout (idéntico al endpoint HTTP). Sin argumentos: este aviso.`)
}

// cliRun ejecuta un subcomando y devuelve su código de salida. No llama a
// os.Exit: así los tests pueden ejercitarlo entero.
func cliRun(args []string) int {
	if len(args) == 0 {
		cliUsage(os.Stderr)
		return exitInput
	}

	switch cmd := args[0]; cmd {
	case "-h", "--help", "help":
		cliUsage(os.Stdout)
		return exitOK
	case "serve":
		return cliServe()
	case "init":
		return cliInit()
	case "doctor":
		return cliDoctor()
	case "pubkey":
		return cliPubkey(hasFlag(args[1:], "--json"))
	case "sign", "pdf", "verifactu-alta", "verifactu-consulta":
		return cliRequest(cmd)
	default:
		fmt.Fprintf(os.Stderr, "comando desconocido: %s\n", cmd)
		cliUsage(os.Stderr)
		return exitInput
	}
}

func hasFlag(args []string, flag string) bool {
	for _, a := range args {
		if a == flag {
			return true
		}
	}
	return false
}

// serveListenAddr devuelve el destino del modo serve: respeta LISTEN si ya
// está puesto y si no fija el socket unix local (WPFE_SOCKET o el camino por
// defecto), dejándolo escrito en LISTEN para que runServer() lo lea.
func serveListenAddr() string {
	if existing := strings.TrimSpace(os.Getenv("LISTEN")); existing != "" {
		return existing
	}
	sock := strings.TrimSpace(os.Getenv("WPFE_SOCKET"))
	if sock == "" {
		sock = DefaultSocketPath
	}
	addr := "unix:" + sock
	_ = os.Setenv("LISTEN", addr)
	return addr
}

// cliServe sirve (por socket unix si LISTEN no está definido: modo local).
func cliServe() int {
	serveListenAddr()
	runServer()
	return exitOK // runServer no retorna salvo error fatal
}

// cliInit da de alta (o reutiliza) keystore + identidad de host e imprime lo
// que hay que fijar en WordPress. Es idempotente: crear dos veces no rota nada.
func cliInit() int {
	cfg, err := loadSignerConfig()
	if err != nil {
		fmt.Fprintln(os.Stderr, "init: "+err.Error())
		return exitKey
	}
	activeConfig = cfg

	fmt.Printf("modo: %s\n", cfg.keyMode)
	if cfg.host != nil {
		certPath, keyPath := hostIdentityPaths()
		fmt.Printf("host_fingerprint: %s\n", cfg.host.Fingerprint)
		fmt.Printf("host_cert: %s\n", certPath)
		fmt.Printf("host_key: %s (0600)\n", keyPath)
	}
	if cfg.keystore != "" {
		fmt.Printf("keystore: %s\n", cfg.keystore)
		if cfg.rewrapped {
			fmt.Println("keystore: re-envuelto con la SPKI actual (rotación de certificado)")
		}
	}
	saltPath, saltPresent, saltRequired, err := keystore.SaltState()
	if err != nil {
		fmt.Fprintln(os.Stderr, "init: salt externo: "+err.Error())
		return exitKey
	}
	switch {
	case saltPath == "":
		fmt.Println("salt_externo: desactivado")
	case saltPresent:
		fmt.Printf("salt_externo: %s\n", saltPath)
	case saltRequired:
		fmt.Printf("salt_externo: %s (obligatorio y ausente)\n", saltPath)
	default:
		fmt.Printf("salt_externo: %s (ausente, opcional)\n", saltPath)
	}
	if id, err := transportKeyID(cfg); err == nil {
		fmt.Printf("transport_key_id: %s\n", id)
	}
	return exitOK
}

// cliDoctor informa del estado y devuelve != 0 si en ESTE host no se puede
// firmar (keystore bloqueado, salt obligatorio ausente, identidad rota…).
// Crea lo que falte, igual que init: es idempotente por diseño.
func cliDoctor() int {
	status := func(key string, value any) { fmt.Printf("%s: %v\n", key, value) }

	status("version", version)

	machineSecret, machineSource, err := keystore.MachineSecret()
	if err != nil {
		fmt.Fprintln(os.Stderr, "doctor: "+err.Error())
		return exitKey
	}
	status("machine_secret", machineSource)
	status("machine_secret_len", len(machineSecret))

	saltPath, saltPresent, saltRequired, err := keystore.SaltState()
	if err != nil {
		fmt.Fprintln(os.Stderr, "doctor: salt externo: "+err.Error())
		return exitKey
	}
	status("salt_path", saltPath)
	status("salt_present", saltPresent)
	status("salt_required", saltRequired)

	cfg, err := loadSignerConfig()
	if err != nil {
		fmt.Fprintln(os.Stderr, "doctor: "+err.Error())
		return exitKey
	}
	activeConfig = cfg

	status("key_mode", cfg.keyMode)
	if cfg.host != nil {
		status("host_fingerprint", cfg.host.Fingerprint)
	} else {
		status("host_fingerprint", "sin identidad de host (modo env/generate)")
	}
	if cfg.keystore != "" {
		status("keystore", cfg.keystore)
		status("keystore_rewrapped", cfg.rewrapped)
	}
	if id, err := transportKeyID(cfg); err == nil {
		status("transport_key_id", id)
	}

	// Estado del socket local (si se usa).
	sock := strings.TrimSpace(os.Getenv("WPFE_SOCKET"))
	if sock == "" {
		sock = DefaultSocketPath
	}
	if info, err := os.Stat(sock); err == nil {
		status("socket", fmt.Sprintf("%s (%04o)", sock, info.Mode().Perm()))
	} else {
		status("socket", sock+" (no existe: se crea al servir)")
	}

	return exitOK
}

// cliPubkey imprime la clave pública de transporte: PEM por defecto y el
// documento de vínculo con --json (lo mismo que /v1/transport-key?format=json,
// para que el cliente no distinga entre ir por red y por CLI).
func cliPubkey(asJSON bool) int {
	cfg, err := loadSignerConfig()
	if err != nil {
		fmt.Fprintln(os.Stderr, "pubkey: "+err.Error())
		return exitKey
	}
	activeConfig = cfg

	if asJSON {
		doc, err := buildTransportKeyDoc(cfg)
		if err != nil {
			fmt.Fprintln(os.Stderr, "pubkey: "+err.Error())
			return exitKey
		}
		encoded, err := json.MarshalIndent(doc, "", "  ")
		if err != nil {
			fmt.Fprintln(os.Stderr, "pubkey: "+err.Error())
			return exitInput
		}
		fmt.Println(string(encoded))
		return exitOK
	}

	pem, err := transportPublicKeyPEM(cfg.privateKey)
	if err != nil {
		fmt.Fprintln(os.Stderr, "pubkey: "+err.Error())
		return exitKey
	}
	fmt.Print(pem)
	return exitOK
}

// cliRequest ejecuta una petición de negocio entera en proceso:
//
//	stdin (JSON) → sellado WPFE1 → envelopeMiddleware → handler → stdout
//
// Es el mismo camino que un request HTTP (incluido el envoltorio), sólo que
// el "transporte" es la tubería del proceso: no hay red por medio.
func cliRequest(cmd string) int {
	handler, path, ok := cliHandler(cmd)
	if !ok {
		fmt.Fprintf(os.Stderr, "comando no soportado: %s\n", cmd)
		return exitInput
	}

	cfg, err := loadSignerConfig()
	if err != nil {
		return cliRequestFail(exitKey, err.Error())
	}
	activeConfig = cfg

	body, err := io.ReadAll(io.LimitReader(os.Stdin, maxBody+1))
	if err != nil {
		return cliRequestFail(exitInput, "no se pudo leer stdin: "+err.Error())
	}
	if len(body) == 0 {
		return cliRequestFail(exitInput, "stdin vacío: se espera el JSON de la petición")
	}
	if int64(len(body)) > maxBody {
		return cliRequestFail(exitInput, "petición demasiado grande")
	}
	if !json.Valid(body) {
		return cliRequestFail(exitInput, "stdin no es JSON válido")
	}
	// El JSON lleva el bundle del usuario: se limpia al salir.
	defer zeroWPFE(body)

	sealed, err := sealWPFE1(body, &cfg.privateKey.PublicKey)
	if err != nil {
		return cliRequestFail(exitKey, "no se pudo sellar la petición: "+err.Error())
	}

	request, err := http.NewRequest(http.MethodPost, path, bytes.NewReader(sealed))
	if err != nil {
		return cliRequestFail(exitInput, err.Error())
	}

	recorder := &bufferedResponse{header: make(http.Header), status: http.StatusOK}
	envelopeMiddleware(handler)(recorder, request)

	if len(recorder.body) > 0 {
		if _, err := os.Stdout.Write(recorder.body); err != nil {
			fmt.Fprintln(os.Stderr, "no se pudo escribir la respuesta: "+err.Error())
			return exitUpstream
		}
	}
	return exitCodeFor(recorder.status)
}

// cliHandler devuelve el handler y la ruta de cada subcomando.
func cliHandler(cmd string) (http.HandlerFunc, string, bool) {
	switch cmd {
	case "sign":
		return signHandler, "/sign", true
	case "pdf":
		return pdfHandler, "/pdf", true
	case "verifactu-alta":
		return verifactuAltaHandler, "/verifactu/alta", true
	case "verifactu-consulta":
		return verifactuConsultaHandler, "/verifactu/consulta", true
	}
	return nil, "", false
}

// exitCodeFor traduce el estado HTTP del handler al código de salida del CLI.
func exitCodeFor(status int) int {
	switch {
	case status >= 200 && status < 300:
		return exitOK
	case status == http.StatusBadRequest:
		return exitInput
	case status == http.StatusServiceUnavailable:
		return exitKey
	default:
		return exitUpstream
	}
}

// cliRequestFail escribe el error como el endpoint ({"error": …}) para que el
// plugin muestre el mensaje igual venga por socket o por CLI.
func cliRequestFail(code int, message string) int {
	encoded, err := json.Marshal(errorResponse{Error: message})
	if err == nil {
		fmt.Println(string(encoded))
	}
	return code
}

// transportKeyID es la huella de la clave de transporte (para init/doctor).
func transportKeyID(cfg *signerConfig) (string, error) {
	doc, err := buildTransportKeyDoc(cfg)
	if err != nil {
		return "", err
	}
	id, _ := doc["transport_key_id"].(string)
	return id, nil
}
