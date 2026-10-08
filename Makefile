# CD/CI de facturae-signer (CI-agnostic: cualquier runner puede llamar a make).
#
#   make ci            fmt + vet + test + build  (local, siempre)
#   make image         imagen OCI con bases fijadas por digest
#   make e2e-local     signer en docker (modo generate) + e2e por HTTP
#   make enclave-local measurements SIMULADAS del binario (sin hardware)
#   make enclave       .eif + measurements reales (SÓLO host EC2 con nitro-cli)
#   make verify DOC=… MEASUREMENTS=… [KEY=…] [NONCE=…] [BINARY=…] [ROOT=…]

GO       ?= go
VERSION  ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
IMAGE    ?= facturae-signer:local
PORT     ?= 18080
EIF      ?= dist/signer.eif

.PHONY: ci fmt vet test build image image-enclave enclave enclave-local e2e-local verify clean

fmt:
	@out=$$(gofmt -l .); if [ -n "$$out" ]; then echo "gofmt pendiente:"; echo "$$out"; exit 1; fi

vet:
	$(GO) vet ./...
	$(GO) vet -tags e2e ./...

test:
	$(GO) test ./...

ci: fmt vet test build

build:
	@mkdir -p dist
	CGO_ENABLED=0 $(GO) build -trimpath -buildvcs=false \
		-ldflags "-s -w -X main.version=$(VERSION)" -o dist/signer .
	@cp dist/signer dist/wpfe-sign
	$(GO) build -trimpath -o dist/facturae-signer-parent ./parent
	$(GO) build -trimpath -o dist/verify ./cmd/verify
	@cd dist && sha256sum signer wpfe-sign facturae-signer-parent verify > SHA256SUMS
	@echo "build OK (version=$(VERSION))"; cat dist/SHA256SUMS

image:
	docker build --build-arg VERSION=$(VERSION) -t $(IMAGE) .

image-enclave: image
	docker build -f Dockerfile.enclave -t $(IMAGE)-enclave .

# SÓLO en un host Nitro (EC2 con nitro-cli y /dev/nitro_enclaves):
# construye el .eif y publica measurements.json con los PCRs reales.
enclave: image-enclave
	@command -v nitro-cli >/dev/null 2>&1 || { \
		echo "✗ nitro-cli no disponible: este target necesita un host EC2 con"; \
		echo "  soporte de enclaves (ver README-enclave.md). Para el bucle local"; \
		echo "  usa: make enclave-local"; exit 1; }
	@mkdir -p dist
	nitro-cli build-enclave --docker-repo $(IMAGE)-enclave --output-file $(EIF)
	hack/measure.sh $(EIF)

# SIN hardware: measurements simuladas (sha256 del binario). Sólo para
# ejercitar cmd/verify y el flujo; NUNCA publicar como mediciones reales.
enclave-local: build
	hack/measure-local.sh dist/signer

# e2e local completo: docker en modo generate + generate→transport-key→sign.
e2e-local: image
	hack/e2e-local.sh $(IMAGE) $(PORT)

# verify DOC=doc.b64 MEASUREMENTS=measurements.json [KEY=key.pem] […]
verify:
	@test -n "$(DOC)" || { echo "falta DOC="; exit 1; }
	@test -n "$(MEASUREMENTS)" || { echo "falta MEASUREMENTS="; exit 1; }
	$(GO) run ./cmd/verify -doc $(DOC) -measurements $(MEASUREMENTS) \
		$(if $(KEY),-key $(KEY)) $(if $(NONCE),-nonce $(NONCE)) \
		$(if $(BINARY),-binary $(BINARY)) $(if $(ROOT),-root $(ROOT))

clean:
	rm -rf dist
