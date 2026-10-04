#!/usr/bin/env sh
# measurements REALES de un .eif — SÓLO host EC2 con nitro-cli.
#   hack/measure.sh dist/signer.eif
# Arranca un enclave SIN --debug-mode (en debug los PCRs del NSM salen a
# cero y describe no sirve), extrae los PCRs con describe-enclaves, escribe
# measurements.json (mode=nitro) y termina el enclave de medida.
set -eu
eif="${1:-dist/signer.eif}"
[ -f "$eif" ] || { echo "✗ no existe $eif" >&2; exit 1; }
command -v nitro-cli >/dev/null 2>&1 || { echo "✗ nitro-cli no disponible" >&2; exit 1; }

name="wpfe-measure-$$"
nitro-cli run-enclave --eif-file "$eif" --cpu-count 2 --memory 256 \
	--enclave-id "$name" >/dev/null
sleep 2
json=$(nitro-cli describe-enclaves --enclave-id "$name")
nitro-cli terminate-enclave --enclave-id "$name" >/dev/null || true

python3 - "$json" <<'PY'
import json, sys
info = json.loads(sys.argv[1])
if isinstance(info, list):
    info = info[0]
m = info.get("Measurements") or info.get("measurements") or {}
def g(k):
    for key in (k, k.lower(), k.upper()):
        if key in m:
            return m[key].lower()
    raise SystemExit(f"✗ {k} no está en describe-enclaves: {sorted(m)}")
pcr0, pcr2 = g("PCR0"), g("PCR2")
if pcr0 == "0"*64:
    raise SystemExit("✗ PCR0 a cero: el enclave sigue en debug sin mediciones reales")
out = {"mode": "nitro", "pcr0": pcr0, "pcr2": pcr2}
open("measurements.json", "w").write(json.dumps(out, indent=2) + "\n")
print(f"measurements.json pcr0={pcr0[:16]}… pcr2={pcr2[:16]}…")
PY
