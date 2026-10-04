package main

import (
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"sync"

	"github.com/fxamacker/cbor/v2"
)

// Protocolo del NSM (/dev/nsm, aws-nitro-enclaves-nsm-api): tramas
// uint32 big-endian con payload CBOR. Límites: public_key ≤1024 B,
// user_data ≤512 B, nonce ≤512 B.
const (
	nsmMaxPublicKey = 1024
	nsmMaxUserData  = 512
	nsmMaxNonce     = 512
)

// attestationProvider produce un documento de attestation que enlaza una
// clave pública con las mediciones (PCRs) del entorno. En el enclave es el
// NSM real; en pruebas, un stub.
type attestationProvider interface {
	GetAttestationDoc(publicKey, userData, nonce []byte) ([]byte, error)
}

// errNSMUnavailable marca la ausencia del dispositivo (modo docker sin
// /dev/nsm): los endpoints de attestation responden 501.
type nsmUnavailableError struct{ path string }

func (e *nsmUnavailableError) Error() string {
	return fmt.Sprintf("NSM no disponible (%s)", e.path)
}

type nsmDevice struct {
	mu   sync.Mutex
	conn io.ReadWriteCloser
}

type nsmRequest struct {
	Version uint64            `cbor:"version"`
	Request nsmRequestPayload `cbor:"request"`
}

type nsmRequestPayload struct {
	Type      string `cbor:"type"`
	PublicKey []byte `cbor:"public_key,omitempty"`
	UserData  []byte `cbor:"user_data,omitempty"`
	Nonce     []byte `cbor:"nonce,omitempty"`
}

type nsmResponse struct {
	Version  uint64             `cbor:"version"`
	Response nsmResponsePayload `cbor:"response"`
}

type nsmResponsePayload struct {
	Error          uint64 `cbor:"error"`
	AttestationDoc []byte `cbor:"attestation_doc"`
}

// nsmErrors: códigos de la cabecera nsm.h del API (mensaje incluye el
// código por si la tabla se desajusta entre versiones).
var nsmErrors = map[uint64]string{
	0:  "NONE",
	1:  "INVALID_REQUEST",
	2:  "UNSUPPORTED",
	3:  "BUSY",
	4:  "INVALID_RESPONSE",
	5:  "IO_ERROR",
	6:  "SIG_MISMATCH",
	7:  "INVALID_ENCODING",
	8:  "USER_ACTION_REQUIRED",
	9:  "BAD_PARAMETERS",
	10: "NO_ENTROPY",
}

// openNSMDevice abre el dispositivo NSM. Devuelve un error NSM si no existe
// (el caller decide: 501 en los endpoints, no fatal al arrancar).
func openNSMDevice(path string) (*nsmDevice, error) {
	if path == "" {
		path = "/dev/nsm"
	}
	conn, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		return nil, &nsmUnavailableError{path: path}
	}
	return &nsmDevice{conn: conn}, nil
}

func (d *nsmDevice) Close() error {
	return d.conn.Close()
}

func (d *nsmDevice) GetAttestationDoc(publicKey, userData, nonce []byte) ([]byte, error) {
	if len(publicKey) > nsmMaxPublicKey {
		return nil, fmt.Errorf("public_key demasiado grande (%d > %d)", len(publicKey), nsmMaxPublicKey)
	}
	if len(userData) > nsmMaxUserData {
		return nil, fmt.Errorf("user_data demasiado grande (%d > %d)", len(userData), nsmMaxUserData)
	}
	if len(nonce) > nsmMaxNonce {
		return nil, fmt.Errorf("nonce demasiado grande (%d > %d)", len(nonce), nsmMaxNonce)
	}

	req := nsmRequest{
		Version: 1,
		Request: nsmRequestPayload{
			Type:      "GetAttestationDoc",
			PublicKey: publicKey,
			UserData:  userData,
			Nonce:     nonce,
		},
	}
	payload, err := cbor.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("codificar petición NSM: %w", err)
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	if err := writeFrame(d.conn, payload); err != nil {
		return nil, fmt.Errorf("escribir en NSM: %w", err)
	}
	respPayload, err := readFrame(d.conn)
	if err != nil {
		return nil, fmt.Errorf("leer del NSM: %w", err)
	}

	var resp nsmResponse
	if err := cbor.Unmarshal(respPayload, &resp); err != nil {
		return nil, fmt.Errorf("respuesta NSM no parseable: %w", err)
	}
	if resp.Response.Error != 0 {
		name, ok := nsmErrors[resp.Response.Error]
		if !ok {
			name = "DESCONOCIDO"
		}
		return nil, fmt.Errorf("NSM devolvió error %d (%s)", resp.Response.Error, name)
	}
	if len(resp.Response.AttestationDoc) == 0 {
		return nil, fmt.Errorf("respuesta NSM sin attestation_doc")
	}
	return resp.Response.AttestationDoc, nil
}

func writeFrame(w io.Writer, payload []byte) error {
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(len(payload)))
	if _, err := w.Write(hdr[:]); err != nil {
		return err
	}
	_, err := w.Write(payload)
	return err
}

func readFrame(r io.Reader) ([]byte, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(hdr[:])
	if n == 0 || n > 1<<20 {
		return nil, fmt.Errorf("trama NSM con longitud no válida: %d", n)
	}
	payload := make([]byte, n)
	if _, err := io.ReadFull(r, payload); err != nil {
		return nil, err
	}
	return payload, nil
}
