FROM golang:1.26-alpine AS build

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY *.go ./
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/signer .

FROM alpine:3.22

RUN apk add --no-cache ca-certificates

COPY --from=build /out/signer /usr/local/bin/signer
# Licencias y avisos de las dependencias (Apache-2.0/BSD): obligación de
# redistribución al distribuir el binario.
COPY licenses/ /usr/local/share/licenses/facturae-signer/

USER nobody

EXPOSE 8080

ENTRYPOINT ["/usr/local/bin/signer"]