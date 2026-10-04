#!/usr/bin/env bash
# S1 — Sonda del contrato de sellado KMS (SÓLO host EC2 con nitro-cli + AWS CLI v2).
#
# Responde con una key desechable y DOS enclaves reales — imagen buena e
# imagen atacante (mismo binario + capa ENV que cambia la medición) — las
# cuatro preguntas de las que depende la arquitectura D′:
#
#   P1  ¿plain Decrypt (sin Recipient) queda denegado?                 → debe SÍ
#   P2  ¿Decrypt(Recipient=doc propio) devuelve sólo
#       CiphertextForRecipient (Plaintext vacío)?                      → debe SÍ
#   P3  ¿Decrypt(Recipient=doc de imagen ATACANTE) se deniega?         → debe SÍ
#       (= INV-2: KMS compara el PCR0 del doc contra la política)
#   P4  ¿Qué ortografía acepta la condición?
#       ImageSha384 (documentada) | PCR0 (plantilla del usuario) | …  → informa
#       y si el pin de PCR2 funciona                                   → informa
#
# Uso:
#   hack/kms-probe.sh --region eu-west-1 [--keep]
#   (antes: nitro-cli-config -i -m 512 -t 4  y  make enclave)
#
# Salida: tabla PASS/FAIL + veredicto según el árbol de decisión:
#   P1=SÍ y P3=SÍ  → INV-2 existe ⇒ arquitectura D′ (KMS puro, sin sealer)
#   P1=NO          → BAIL: ninguna política nos protege ⇒ mantener v1 (efímero)
#   P2 falla       → revisar ortografía/permisos (P4 informa)
set -euo pipefail
cd "$(dirname "$0")/.."

REGION="${AWS_REGION:-${AWS_DEFAULT_REGION:-}}"
KEEP=0
while [ $# -gt 0 ]; do
	case "$1" in
		--region) REGION="$2"; shift 2 ;;
		--keep)   KEEP=1; shift ;;
		-h|--help) sed -n '2,25p' "$0"; exit 0 ;;
		*) echo "opción desconocida: $1 (¿--region <r>?) " >&2; exit 2 ;;
	esac
done
[ -n "$REGION" ] || REGION=$(aws configure get region 2>/dev/null || true)
[ -n "$REGION" ] || { echo "✗ falta la región (--region o AWS_REGION)" >&2; exit 1; }

for tool in aws nitro-cli docker python3 curl; do
	command -v "$tool" >/dev/null || { echo "✗ falta $tool" >&2; exit 1; }
done
aws --version 2>&1 | grep -q "aws-cli/2" || { echo "✗ hace falta AWS CLI v2 (parámetro --recipient)"; exit 1; }

export AWS_REGION="$REGION" AWS_DEFAULT_REGION="$REGION"
BENIGN_PORT=18090
ATTACK_PORT=18091
LIVE_CID="" ATTACK_CID="" PARENT1_PID="" PARENT2_PID="" KEY_ID=""

cleanup() {
	set +e
	[ -n "$PARENT1_PID" ] && kill "$PARENT1_PID" 2>/dev/null
	[ -n "$PARENT2_PID" ] && kill "$PARENT2_PID" 2>/dev/null
	[ -n "$LIVE_CID" ]    && nitro-cli terminate-enclave --enclave-id "$LIVE_CID" >/dev/null 2>&1
	[ -n "$ATTACK_CID" ]  && nitro-cli terminate-enclave --enclave-id "$ATTACK_CID" >/dev/null 2>&1
	if [ "$KEEP" != 1 ] && [ -n "$KEY_ID" ]; then
		aws kms schedule-key-deletion --key-id "$KEY_ID" --pending-window-in-days 7 >/dev/null 2>&1
		echo "(key $KEY_ID programada para borrado en 7 días; --keep para conservarla)"
	fi
}
trap cleanup EXIT

get_cid() { # <enclave-id> → CID (EnclaveID de describe-enclaves)
	nitro-cli describe-enclaves --enclave-id "$1" | python3 -c '
import json,sys
d=json.load(sys.stdin); d=d[0] if isinstance(d,list) else d
print(d["EnclaveID"])'
}

get_pcrs() { # <enclave-id> → "pcr0 pcr2"
	nitro-cli describe-enclaves --enclave-id "$1" | python3 -c '
import json,sys
d=json.load(sys.stdin); d=d[0] if isinstance(d,list) else d
m=d.get("Measurements") or d.get("measurements") or {}
print(m.get("PCR0", m.get("pcr0","")).lower(), m.get("PCR2", m.get("pcr2","")).lower())'
}

wait_health() { # <port>
	for _ in $(seq 1 40); do
		curl -fsS "http://127.0.0.1:$1/health" >/dev/null 2>&1 && return 0
		sleep 0.25
	done
	return 1
}

fetch_doc() { # <port> <out.json>
	curl -fsS "http://127.0.0.1:$1/v1/attestation?nonce=b64:$(head -c 24 /dev/urandom | base64)" -o "$2"
}

raw_doc() { # <json> <cbor-out>
	python3 -c '
import json,base64,sys
d=json.load(open(sys.argv[1]))
open(sys.argv[2],"wb").write(base64.b64decode(d["attestation_doc"]))' "$1" "$2"
}

put_policy() { # <key-id> <condition-key> <pcr0-hex> [ <pcr2-hex> ]
	local key="$1" cond="$2" pcr0="$3" pcr2="${4:-}"
	python3 - "$cond" "$pcr0" "$pcr2" <<'PY' > /tmp/wpfe-kms-probe-policy.json
import json, sys, subprocess
cond, pcr0, pcr2 = sys.argv[1], sys.argv[2], sys.argv[3]
acct = subprocess.check_output(
    ["aws", "sts", "get-caller-identity", "--query", "Account", "--output", "text"],
    text=True).strip()
caller = subprocess.check_output(
    ["aws", "sts", "get-caller-identity", "--query", "Arn", "--output", "text"],
    text=True).strip()
ctx = {"Condition": {f"StringEqualsIgnoreCase": {f"kms:RecipientAttestation:{cond}": pcr0}}}
if pcr2:
    ctx["Condition"]["StringEqualsIgnoreCase"][f"kms:RecipientAttestation:PCR2"] = pcr2
stmts = [
    {"Sid": "ProbeEncryptForCanary", "Effect": "Allow",
     "Principal": {"AWS": caller}, "Action": "kms:Encrypt", "Resource": "*"},
    {"Sid": "ProbeDecryptOnlyAttested", "Effect": "Allow",
     "Principal": {"AWS": caller}, "Action": "kms:Decrypt",
     "Resource": "*", **ctx},
]
print(json.dumps({
    "Version": "2012-10-17",
    "Id": "wpfe-kms-probe",
    "Statement": stmts,
}, indent=2))
PY
	aws kms put-key-policy --key-id "$key" --policy-name default \
		--policy "file:///tmp/wpfe-kms-probe-policy.json" >/dev/null
}

decrypt_recipient() { # <key-id> <canary> <doc.cbor> → stdout json; rc!=0 si denegado
	aws kms decrypt --key-id "$1" --ciphertext-blob "fileb://$2" \
		--recipient "AttestationDocument=fileb://$3,KeyEncryptionAlgorithm=RSAES_OAEP_SHA_256" \
		--output json 2>/tmp/wpfe-kms-probe-decrypt.err || return 1
}

echo "== S1: sonda KMS (región $REGION)"
echo "== 0/5 make enclave (imagen + measurements reales)"
make enclave

echo "== 1/5 enclave BENIGN (doc + PCRs)"
nitro-cli run-enclave --eif-file dist/signer.eif --cpu-count 2 --memory 256 \
	--enclave-id wpfe-probe-benign >/dev/null
LIVE_CID=$(get_cid wpfe-probe-benign)
ENCLAVE_CID="$LIVE_CID" RELAY_VSOCK_PORT=0 INBOUND_LISTEN="127.0.0.1:$BENIGN_PORT" \
	nohup dist/facturae-signer-parent > /tmp/wpfe-probe-parent1.log 2>&1 &
PARENT1_PID=$!
wait_health "$BENIGN_PORT" || { echo "✗ benign sin health (¿nitro-cli-config -i -m 512 -t 4?)" >&2; exit 1; }
fetch_doc "$BENIGN_PORT" dist/probe-doc-benign.json
raw_doc dist/probe-doc-benign.json dist/probe-doc-benign.cbor
read -r BENIGN_PCR0 BENIGN_PCR2 <<<"$(get_pcrs "$LIVE_CID")"
echo "   pcr0=$BENIGN_PCR0"
[ -n "$BENIGN_PCR0" ] && [ "$BENIGN_PCR0" != "0000000000000000000000000000000000000000000000000000000000000000" ] \
	|| { echo "✗ PCR0 vacío o a ceros: ¿enclave en modo debug?" >&2; exit 1; }

echo "== 2/5 enclave ATACANTE (misma imagen + capa ENV ⇒ distinto hash)"
printf 'FROM facturae-signer:local-enclave\nENV WPFE_PROBE_ATTACKER=1\n' \
	| docker build -t wpfe-probe-attacker:latest - >/dev/null
nitro-cli build-enclave --docker-repo wpfe-probe-attacker:latest \
	--output-file dist/attacker.eif >/dev/null
nitro-cli run-enclave --eif-file dist/attacker.eif --cpu-count 2 --memory 256 \
	--enclave-id wpfe-probe-attack >/dev/null
ATTACK_CID=$(get_cid wpfe-probe-attack)
ENCLAVE_CID="$ATTACK_CID" RELAY_VSOCK_PORT=0 INBOUND_LISTEN="127.0.0.1:$ATTACK_PORT" \
	nohup dist/facturae-signer-parent > /tmp/wpfe-probe-parent2.log 2>&1 &
PARENT2_PID=$!
wait_health "$ATTACK_PORT" || { echo "✗ atacante sin health" >&2; exit 1; }
fetch_doc "$ATTACK_PORT" dist/probe-doc-attacker.json
raw_doc dist/probe-doc-attacker.json dist/probe-doc-attacker.cbor
read -r ATTACK_PCR0 _ <<<"$(get_pcrs "$ATTACK_CID")"
echo "   pcr0=$ATTACK_PCR0"
if [ "$ATTACK_PCR0" = "$BENIGN_PCR0" ]; then
	echo "✗ los PCRs coinciden: la capa ENV no cambió la medición; prueba con otro cambio (p. ej. distinto ENTRYPOINT)" >&2
	exit 1
fi

echo "== 3/5 key desechable + matriz de política"
KEY_ID=$(aws kms create-key --description "wpfe-kms-probe-$(date +%s)" \
	--query KeyMetadata.KeyId --output text)
echo "   key=$KEY_ID"
CANARY_PT=/tmp/wpfe-kms-probe-canary.bin
aws kms encrypt --key-id "$KEY_ID" --plaintext "canario-de-sonda" \
	--ciphertext-blob "fileb://$CANARY_PT" >/dev/null

RESULTS=()
check() { # <nombre> <esperado(SI|NO)> <comando...>  → acumula RESULTS
	local name="$1" want="$2"; shift 2
	local out rc=0
	out=$("$@" 2>&1) || rc=$?
	local got=NO
	[ "$rc" -eq 0 ] && got=SI
	local verdict=FAIL
	[ "$got" = "$want" ] && verdict=PASS
	RESULTS+=("$verdict|$name (obtenido=$got, esperado=$want)")
	printf '   %-6s %s\n' "$verdict" "$name (obtenido=$got, esperado=$want)"
}

# P1: plain decrypt SIN Recipient → AccessDenied (condición no satisfecha)
put_policy "$KEY_ID" "ImageSha384" "$BENIGN_PCR0"
check "P1 plain Decrypt denegado" NO \
	aws kms decrypt --key-id "$KEY_ID" --ciphertext-blob "fileb://$CANARY_PT" --output json

# P2: Recipient con doc propio → sólo CiphertextForRecipient
p2_ok() {
	local out
	if out=$(decrypt_recipient "$KEY_ID" "$CANARY_PT" "$1"); then
		python3 -c '
import json,sys
d=json.load(sys.stdin)
sys.exit(0 if (d.get("CiphertextForRecipient") and not d.get("Plaintext")) else 1)' <<<"$out"
		return $?
	fi
	return 1
}
if p2_ok dist/probe-doc-benign.cbor; then
	printf '   %-6s %s\n' PASS "P2 Recipient doc propio → CiphertextForRecipient (condición: ImageSha384)"
	RESULTS+=("PASS|P2 Recipient doc propio")
else
	printf '   %-6s %s\n' FAIL "P2 Recipient doc propio (condición: ImageSha384)"
	RESULTS+=("FAIL|P2 Recipient doc propio (ImageSha384)")
fi

# P4: ortografías de condición si P2 falló (o para informar PCR0 literal)
for cond in ImageSha384 PCR0; do
	[ "$cond" = "ImageSha384" ] && continue  # ya probada
	put_policy "$KEY_ID" "$cond" "$BENIGN_PCR0"
	if p2_ok dist/probe-doc-benign.cbor; then
		printf '   %-6s %s\n' PASS "P4 ortografía aceptada: kms:RecipientAttestation:$cond (además de ImageSha384 si P2 ya pasó)"
		RESULTS+=("PASS|P4 ortografía $cond")
	fi
done

# P4b: pin de PCR2 (si la ortografía base funciona)
put_policy "$KEY_ID" "ImageSha384" "$BENIGN_PCR0" "$BENIGN_PCR2"
if p2_ok dist/probe-doc-benign.cbor; then
	printf '   %-6s %s\n' PASS "P4b pin doble ImageSha384+PCR2 aceptado"
	RESULTS+=("PASS|P4b pin ImageSha384+PCR2")
else
	printf '   %-6s %s\n' FAIL "P4b pin doble ImageSha384+PCR2 (¿clave PCR2 inexistente?)"
	RESULTS+=("FAIL|P4b pin ImageSha384+PCR2")
fi

# P3: Recipient con doc ATACANTE → AccessDenied (el corazón de INV-2)
put_policy "$KEY_ID" "ImageSha384" "$BENIGN_PCR0"
check "P3 Recipient doc ATACANTE denegado" NO \
	bash -c "aws kms decrypt --key-id '$KEY_ID' --ciphertext-blob 'fileb://$CANARY_PT' \
		--recipient 'AttestationDocument=fileb://dist/probe-doc-attacker.cbor,KeyEncryptionAlgorithm=RSAES_OAEP_SHA_256' \
		--output json"

echo
echo "== 5/5 veredicto"
P1=NO; P2=NO; P3=NO
for r in "${RESULTS[@]}"; do
	case "$r" in
		"PASS|P1 plain Decrypt denegado"*) P1=SI ;;
		"PASS|P2 Recipient doc propio"*)   P2=SI ;;
		"PASS|P3 Recipient doc ATACANTE denegado"*) P3=SI ;;
	esac
done
echo "   P1 plain-decrypt denegado : $P1"
echo "   P2 unwrap propio          : $P2"
echo "   P3 imagen atacante deneg. : $P3"
echo
if [ "$P1" = SI ] && [ "$P2" = SI ] && [ "$P3" = SI ]; then
	echo "✓ INV-2 CONFIRMADO: KMS compara el PCR0 del doc contra la política."
	echo "  ⇒ arquitectura D′ (sellado KMS puro, sin sealer) — implementar S2 con"
	echo "    deploy/kms-policy.json (sustituir placeholders con los PCRs de arriba)."
elif [ "$P1" = NO ]; then
	echo "✗ P1 falló: plain Decrypt NO está denegado ⇒ BAIL: no se habilita sellado;"
	echo "  mantener modo efímero (v1: re-subir certificado al reiniciar)."
else
	echo "⚠ matriz parcial: revisar ortografía de condición (P4) / permisos / P3."
	echo "  Si P3=SI pero P2=NO → no hay unwrap posible con nuestra imagen."
	echo "  Si P3=NO (atacante aceptado) ⇒ INV-2 NO existe ⇒ arquitectura D (sealer off-host)."
fi
