// verify valida un documento de attestation del NSM (o una simulación local)
// contra las mediciones publicadas del release:
//
//	go run ./cmd/verify -doc doc.b64 -measurements measurements.json \
//	    [-key pubkey.pem] [-nonce N] [-binary signer] [-root aws-root.pem]
//
// Modo "nitro": compara pcr0/pcr2 (hex) con measurements.json del release.
// Modo "simulated" (make enclave-local): compara el sha256 del binario.
// -key: la public_key embebida en el doc debe ser exactamente ese SPKI.
// -root: además intenta cadena (certificate/cabundle → raíz) y firma del
// documento (codificaciones canónicas RFC7049 y RFC8949; mejor esfuerzo).
package main

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/fxamacker/cbor/v2"
)

type options struct {
	doc          string
	measurements string
	key          string
	nonce        string
	binary       string
	root         string
}

type measurements struct {
	Mode         string `json:"mode"`
	PCR0         string `json:"pcr0,omitempty"`
	PCR2         string `json:"pcr2,omitempty"`
	BinarySHA256 string `json:"binary_sha256,omitempty"`
	Note         string `json:"note,omitempty"`
}

func main() {
	var o options
	flag.StringVar(&o.doc, "doc", "", "fichero con el attestation doc (base64 o binario)")
	flag.StringVar(&o.measurements, "measurements", "measurements.json", "mediciones publicadas del release")
	flag.StringVar(&o.key, "key", "", "PEM SPKI esperada (transport key)")
	flag.StringVar(&o.nonce, "nonce", "", "nonce esperado (base64 o crudo)")
	flag.StringVar(&o.binary, "binary", "", "binario (modo simulated)")
	flag.StringVar(&o.root, "root", "", "PEM de la raíz para cadena+firma (opcional)")
	flag.Parse()

	if err := run(o); err != nil {
		fmt.Fprintf(os.Stderr, "FAIL: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("OK: documento verificado contra las mediciones")
}

func run(o options) error {
	if o.doc == "" {
		return fmt.Errorf("-doc es obligatorio")
	}
	docRaw, err := os.ReadFile(o.doc)
	if err != nil {
		return err
	}
	docBytes := docInputBytes(docRaw)

	var doc map[string]any
	if err := cbor.Unmarshal(docBytes, &doc); err != nil {
		return fmt.Errorf("el documento no es CBOR válido: %w", err)
	}

	var m measurements
	mb, err := os.ReadFile(o.measurements)
	if err != nil {
		return fmt.Errorf("lectura de measurements: %w", err)
	}
	if err := json.Unmarshal(mb, &m); err != nil {
		return fmt.Errorf("measurements inválidos: %w", err)
	}

	switch m.Mode {
	case "nitro-debug":
		// Documento de un enclave en --debug-mode: NSM devuelve PCRs a cero.
		// Sirve para probar el flujo en EC2; NUNCA para confiar en datos.
		zero := strings.Repeat("0", 64)
		if err := expectHexField(doc, "pcr0", zero); err != nil {
			return fmt.Errorf("modo debug: se esperaban PCRs a cero: %w", err)
		}
		fmt.Fprintln(os.Stderr, "⚠ DEBUG ENCLAVE: PCRs a cero — este documento NO sirve para confiar (sólo e2e)")
	case "nitro":
		if err := expectHexField(doc, "pcr0", m.PCR0); err != nil {
			return err
		}
		if err := expectHexField(doc, "pcr2", m.PCR2); err != nil {
			return err
		}
		fmt.Println("OK  pcr0 y pcr2 coinciden con measurements.json (nitro)")
	case "simulated":
		if o.binary == "" {
			return fmt.Errorf("modo simulated: falta -binary")
		}
		bin, err := os.ReadFile(o.binary)
		if err != nil {
			return err
		}
		sum32 := sha256.Sum256(bin)
		sum := hex.EncodeToString(sum32[:])
		if !strings.EqualFold(sum, m.BinarySHA256) {
			return fmt.Errorf("binary_sha256 no coincide: doc=%s binario=%s", m.BinarySHA256, sum)
		}
		fmt.Println("OK  sha256 del binario coincide (SIMULACIÓN local: no es una medición de hardware)")
	default:
		return fmt.Errorf("mode desconocido en measurements: %q", m.Mode)
	}

	if o.key != "" {
		want, err := spkiDERFromFile(o.key)
		if err != nil {
			return err
		}
		got, ok := doc["public_key"].([]byte)
		if !ok || len(got) == 0 {
			return fmt.Errorf("el documento no lleva public_key enlazada")
		}
		if string(got) != string(want) {
			return fmt.Errorf("public_key del documento ≠ clave esperada (el doc pertenece a OTRA clave/instancia)")
		}
		fmt.Println("OK  public_key enlazada en el documento coincide con la clave esperada")
	}

	if o.nonce != "" {
		want := decodeNonce(o.nonce)
		got, _ := doc["nonce"].([]byte)
		if string(got) != string(want) {
			return fmt.Errorf("nonce no coincide (¿replay?)")
		}
		fmt.Println("OK  nonce coincide")
	}

	if o.root != "" {
		if err := verifyChainAndSignature(doc, o.root); err != nil {
			return err
		}
		fmt.Println("OK  cadena y firma del documento verificadas")
	}
	return nil
}

func expectHexField(doc map[string]any, name, want string) error {
	if want == "" {
		return fmt.Errorf("measurements sin %s", name)
	}
	raw, ok := doc[name].([]byte)
	if !ok || len(raw) == 0 {
		return fmt.Errorf("el documento no lleva %s", name)
	}
	got := hex.EncodeToString(raw)
	if !strings.EqualFold(got, want) {
		return fmt.Errorf("%s no coincide: esperado %s…, obtenido %s…", name, trunc(want), trunc(got))
	}
	return nil
}

func trunc(s string) string {
	if len(s) > 12 {
		return s[:12]
	}
	return s
}

func spkiDERFromFile(path string) ([]byte, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(b)
	if block == nil {
		return nil, fmt.Errorf("%s no es PEM", path)
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("SPKI inválida: %w", err)
	}
	return x509.MarshalPKIXPublicKey(pub)
}

// verifyChainAndSignature: cadena mejor esfuerzo (directa o vía cabundle)
// y firma sobre el doc sin "signature" con las dos codificaciones
// deterministas habituales (RFC7049 canónica y RFC8949 core).
func verifyChainAndSignature(doc map[string]any, rootPath string) error {
	certDER, _ := doc["certificate"].([]byte)
	if len(certDER) == 0 {
		return fmt.Errorf("el documento no lleva certificate")
	}
	leaf, err := x509.ParseCertificate(certDER)
	if err != nil {
		return fmt.Errorf("certificate ilegible: %w", err)
	}

	rootPEM, err := os.ReadFile(rootPath)
	if err != nil {
		return err
	}
	block, _ := pem.Decode(rootPEM)
	if block == nil {
		return fmt.Errorf("%s no es PEM", rootPath)
	}
	root, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return fmt.Errorf("raíz inválida: %w", err)
	}

	chainOK := false
	if err := leaf.CheckSignatureFrom(root); err == nil {
		chainOK = true
	} else {
		if bundle, ok := doc["cabundle"].([]any); ok {
			for _, raw := range bundle {
				b, ok := raw.([]byte)
				if !ok {
					continue
				}
				inter, err := x509.ParseCertificate(b)
				if err != nil {
					continue
				}
				if leaf.CheckSignatureFrom(inter) == nil && (inter.CheckSignatureFrom(root) == nil || inter.Equal(root)) {
					chainOK = true
					break
				}
			}
		}
	}
	if !chainOK {
		return fmt.Errorf("la cadena del certificate no ancla a la raíz dada")
	}

	sig, _ := doc["signature"].([]byte)
	if len(sig) == 0 {
		return fmt.Errorf("el documento no lleva signature")
	}
	unsigned := make(map[string]any, len(doc))
	for k, v := range doc {
		if k != "signature" {
			unsigned[k] = v
		}
	}
	alg, _ := doc["signature_algorithm"].(string)
	hash, err := parseSigAlg(alg)
	if err != nil {
		return err
	}

	modes := []cbor.EncMode{}
	for _, opts := range []cbor.EncOptions{
		cbor.CanonicalEncOptions(), // RFC 7049 canónica
		cbor.CoreDetEncOptions(),   // RFC 8949 determinista
	} {
		em, err := opts.EncMode()
		if err != nil {
			continue
		}
		modes = append(modes, em)
	}
	for _, em := range modes {
		var buf bytes.Buffer
		if err := em.NewEncoder(&buf).Encode(unsigned); err != nil {
			continue
		}
		if verifyWithKey(leaf.PublicKey, hash, buf.Bytes(), sig) {
			return nil
		}
	}
	return fmt.Errorf("firma del documento no verificable (alg=%q, codificaciones canónicas probadas)", alg)
}

// parseSigAlg traduce "SHA384withECDSA"/"SHA256withRSA"/… a hash.
func parseSigAlg(alg string) (crypto.Hash, error) {
	// Devuelve (hash para verificar con PublicKey.Verify, id crypto.Hash).
	upper := strings.ToUpper(alg)
	switch {
	case strings.Contains(upper, "SHA256") && strings.Contains(upper, "ECDSA"):
		return crypto.SHA256, nil
	case strings.Contains(upper, "SHA384") && strings.Contains(upper, "ECDSA"):
		return crypto.SHA384, nil
	case strings.Contains(upper, "SHA512") && strings.Contains(upper, "ECDSA"):
		return crypto.SHA512, nil
	case strings.Contains(upper, "SHA256") && strings.Contains(upper, "RSA"):
		return crypto.SHA256, nil
	case strings.Contains(upper, "SHA384") && strings.Contains(upper, "RSA"):
		return crypto.SHA384, nil
	case strings.Contains(upper, "SHA512") && strings.Contains(upper, "RSA"):
		return crypto.SHA512, nil
	}
	return 0, fmt.Errorf("signature_algorithm no soportada: %q", alg)
}

func verifyWithKey(pub any, hash crypto.Hash, payload, sig []byte) bool {
	switch k := pub.(type) {
	case *ecdsa.PublicKey:
		digest := hash.New()
		digest.Write(payload)
		return ecdsa.VerifyASN1(k, digest.Sum(nil), sig)
	case *rsa.PublicKey:
		digest := hash.New()
		digest.Write(payload)
		err := rsa.VerifyPKCS1v15(k, hash, digest.Sum(nil), sig)
		return err == nil
	default:
		return false
	}
}

// docInputBytes acepta: CBOR crudo, base64 crudo, o el wrapper JSON que
// devuelve el endpoint {"attestation_doc": "<b64>"}.
func docInputBytes(raw []byte) []byte {
	trim := strings.TrimSpace(string(raw))
	if strings.HasPrefix(trim, "{") {
		var w struct {
			Doc string `json:"attestation_doc"`
		}
		if err := json.Unmarshal([]byte(trim), &w); err == nil && w.Doc != "" {
			if b, err := base64.StdEncoding.DecodeString(w.Doc); err == nil {
				return b
			}
		}
	}
	return decodeMaybeBase64(raw)
}

// decodeNonce: "b64:…" | "b64url:…" | crudo (misma regla que el signer).
func decodeNonce(s string) []byte {
	if s == "" {
		return nil
	}
	if rest, ok := strings.CutPrefix(s, "b64:"); ok {
		if b, err := base64.StdEncoding.DecodeString(rest); err == nil {
			return b
		}
		return []byte(s)
	}
	if rest, ok := strings.CutPrefix(s, "b64url:"); ok {
		if b, err := base64.RawURLEncoding.DecodeString(rest); err == nil {
			return b
		}
		return []byte(s)
	}
	return []byte(s)
}

func decodeMaybeBase64(b []byte) []byte {
	s := strings.TrimSpace(string(b))
	for _, enc := range []*base64.Encoding{
		base64.StdEncoding, base64.URLEncoding, base64.RawStdEncoding, base64.RawURLEncoding,
	} {
		if dec, err := enc.DecodeString(s); err == nil && len(dec) > 0 {
			return dec
		}
	}
	return b
}
