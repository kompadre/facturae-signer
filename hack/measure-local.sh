#!/usr/bin/env sh
# measurements SIMULADAS (sha256 del binario) — para make enclave-local.
# NO son PCRs de nitro-cli: nunca publicar este fichero como mediciones
# reales de un release (el modo "simulated" de cmd/verify lo delata).
set -eu
bin="${1:-dist/signer}"
[ -f "$bin" ] || { echo "✗ no existe $bin (make build)" >&2; exit 1; }
sum=$(sha256sum "$bin" | cut -d' ' -f1)
cat > measurements.json <<JSON
{
  "mode": "simulated",
  "binary_sha256": "$sum",
  "note": "SIMULACIÓN local (make enclave-local): NO es PCR0/PCR2 de nitro-cli. Sustituir por measurements reales (make enclave en host EC2) antes de confiar."
}
JSON
echo "measurements.json (simulado) binary_sha256=$sum"
