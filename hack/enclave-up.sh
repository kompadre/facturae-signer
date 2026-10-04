#!/usr/bin/env bash
# Bring-up del signer en Nitro Enclave (SÓLO host EC2 con nitro-cli).
#
#   hack/enclave-up.sh [--debug] [--cpu N] [--memory MB] [--root aws-root.pem]
#
#   --debug: arranca con --debug-mode (consola: nitro-cli console <id>;
#            el attestation doc sale con PCRs A CERO — se verifica con un
#            measurements de modo nitro-debug y NUNCA sirve para confiar).
#   --root:  PEM de la raíz AWS para verificar cadena+firma del doc.
#
# Pasos: make enclave (.eif + measurements reales) → run-enclave → parent
# (ENCLAVE_CID) → health → transport-key → attestation (nonce) → cmd/verify.
set -euo pipefail
cd "$(dirname "$0")/.."

DEBUG=0; CPU=2; MEM=256; ROOT=""
while [ $# -gt 0 ]; do
	case "$1" in
		--debug) DEBUG=1; shift ;;
		--cpu) CPU="$2"; shift 2 ;;
		--memory) MEM="$2"; shift 2 ;;
		--root) ROOT="$2"; shift 2 ;;
		*) echo "opción desconocida: $1" >&2; exit 2 ;;
	esac
done

command -v nitro-cli >/dev/null 2>&1 || { echo "✗ nitro-cli no disponible (EC2 con enclaves)" >&2; exit 1; }

echo "== build + measurements reales (.eif, run de medida sin debug)"
make enclave

EIF=dist/signer.eif
ID=wpfe-$$
RUN_ARGS=(--eif-file "$EIF" --cpu-count "$CPU" --memory "$MEM" --enclave-id "$ID")
[ "$DEBUG" = 1 ] && RUN_ARGS+=(--debug-mode)
echo "== run-enclave ${RUN_ARGS[*]}"
nitro-cli run-enclave "${RUN_ARGS[@]}" >/dev/null
trap 'nitro-cli terminate-enclave --enclave-id "$ID" >/dev/null 2>&1 || true' EXIT
sleep 2

CID=$(nitro-cli describe-enclaves --enclave-id "$ID" | python3 -c '
import json,sys
info=json.load(sys.stdin)
info=info[0] if isinstance(info,list) else info
print(info.get("EnclaveID") or info.get("EnclaveID ".strip()) or "")
')
[ -n "$CID" ] || { echo "✗ no se pudo obtener el CID del enclave" >&2; exit 1; }
echo "== enclave CID=$CID"

echo "== parent (background)"
ENCLAVE_CID="$CID" nohup dist/facturae-signer-parent >/tmp/wpfe-parent.log 2>&1 &
PARENT_PID=$!
sleep 1

PARENT=${PARENT_HTTP:-http://127.0.0.1:8080}
for i in $(seq 1 30); do curl -fsS "$PARENT/health" >/dev/null 2>&1 && break; sleep 0.5; done
curl -fsS "$PARENT/health" >/dev/null || { echo "✗ parent/enclave sin health"; tail -5 /tmp/wpfe-parent.log; exit 1; }
echo "✓ health OK"

curl -fsS "$PARENT/v1/transport-key" -o dist/transport-key.pem
echo "✓ transport-key → dist/transport-key.pem (pegar en Ajustes → Clave Pública)"

NONCE_B64="b64:$(head -c 24 /dev/urandom | base64)"
curl -fsS "$PARENT/v1/attestation?nonce=$NONCE_B64" -o dist/attestation.json
echo "✓ attestation doc → dist/attestation.json"

if [ "$DEBUG" = 1 ]; then
	cat > dist/measurements-debug.json <<JSON
{"mode": "nitro-debug"}
JSON
	echo "⚠ MODO DEBUG: PCRs a cero esperados — verify con mode nitro-debug (sólo e2e)"
	MEAS=dist/measurements-debug.json
else
	MEAS=measurements.json
fi

go run ./cmd/verify -doc dist/attestation.json -measurements "$MEAS" \
	-key dist/transport-key.pem -nonce "$NONCE_B64" ${ROOT:+-root "$ROOT"}
echo
echo "✓ TODO OK — signing_url para WordPress: $PARENT"
echo "  (consola del enclave: nitro-cli console --enclave-id $ID${DEBUG:+ disponible en modo debug})"
kill "$PARENT_PID" 2>/dev/null || true
