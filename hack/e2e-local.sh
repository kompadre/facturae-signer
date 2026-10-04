#!/usr/bin/env sh
# e2e local: signer docker en modo generate + flujo completo por HTTP
# (health → transport-key → attestation 501 → sign). Requiere docker.
set -eu
IMAGE="${1:-facturae-signer:local}"
PORT="${2:-18080}"
NAME="wpfe-e2e"

docker rm -f "$NAME" >/dev/null 2>&1 || true
docker run -d --name "$NAME" -e WPFE_KEY_MODE=generate -p "$PORT:8080" "$IMAGE" >/dev/null
trap 'docker rm -f "$NAME" >/dev/null 2>&1' EXIT

i=0
until curl -fsS "http://127.0.0.1:$PORT/health" >/dev/null 2>&1; do
	i=$((i+1)); [ "$i" -lt 40 ] || { echo "✗ el signer no arrancó"; docker logs "$NAME" | tail -5; exit 1; }
	sleep 0.25
done

E2E_URL="http://127.0.0.1:$PORT" go test -tags e2e -count=1 -timeout 60s .
echo "✓ e2e-local OK (generate + transport-key + sign por HTTP)"
