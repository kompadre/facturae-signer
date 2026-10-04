# Imágenes fijadas por DIGEST (no por tag): PCR0/PCR2 del enclave miden el
# hash de esta imagen; un tag flotante volvería irreproducibles los
# measurements publicados por release.
# Actualizar el digest = cambiar de versión de base DE LIBRE de forma
# explícita en un commit (re-medir después).
FROM golang:1.26-alpine@sha256:8ac98ca534ac3f51e1f420a1dd2c15e74c75cfa0f23f3ad27eb5d7236c349a0c AS build

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY *.go ./

# VERSION entra en el binario (-X main.version) y viaja en el user_data del
# attestation doc: las mediciones son por release (publicar measurements.json
# junto al tag).
ARG VERSION=dev
RUN CGO_ENABLED=0 go build -trimpath -buildvcs=false \
    -ldflags="-s -w -X main.version=${VERSION}" -o /out/signer .

FROM alpine:3.22@sha256:5291449c3df73caf6ed85e649dec1b9e818b39a5d8c871e97afc13e9cd5e8fa8

RUN apk add --no-cache ca-certificates

COPY --from=build /out/signer /usr/local/bin/signer

# Licencias y avisos de las dependencias (Apache-2.0/BSD/MIT): obligación de
# redistribución al distribuir el binario.
COPY licenses/ /usr/local/share/licenses/facturae-signer/

USER nobody

EXPOSE 8080

ENTRYPOINT ["/usr/local/bin/signer"]
