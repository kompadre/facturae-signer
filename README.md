# facturae-signer

Microservicio Go de firma para el ecosistema español **Facturae / VeriFactu /
FACe**: firma XAdES de facturas Facturae 3.2.x, ciclo de vida VeriFactu
(alta · anulación · consulta) y generación del PDF VERI\*FACTU — expuesto como
API JSON y pensado para **no vivir dentro de WordPress**.

Es la pieza de firma de la pila **WPFacturaE**. El contrato de seguridad es
simple: WordPress sólo maneja **sobres cifrados** (WPFE1) y el material de
firma —incluida la clave privada del .p12 del cliente— sólo existe dentro del
proceso firmador, idealmente dentro de un [AWS Nitro Enclave](README-enclave.md).

> **Estado**: probado en el entorno de pruebas de la AEAT (alta, anulación y
> consulta de registros VeriFactu), validadores oficiales AOC (Facturae
> 3.2.1 + perfil XAdES rsa-sha1) y envío a FACe en modo test. Proyecto sin
> relación oficial con la AEAT, la AOC ni FACe. Ver «Estado y límites».

## Endpoints

| Método | Ruta | Qué hace | Cuerpo (JSON) |
|---|---|---|---|
| `POST` | `/sign` | Firma un XML Facturae (XAdES enveloped) | `xml` y `certificate` (base64) → `signed_xml` (base64) |
| `POST` | `/pdf` | Renderiza el PDF VERI\*FACTU de una factura | `xml` (base64, factura firmada) |
| `POST` | `/verifactu/alta` | Da de alta o anula un registro VeriFactu | `certificate` + `record` (`kind`: `alta`/`anulacion`) |
| `POST` | `/verifactu/consulta` | Consulta estado (paginación con `clave_paginacion`) | `certificate` + `nif`/`nombre`/`fecha`/`numero`/`clave_paginacion` |
| `GET` | `/health` | Liveness | — → `ok` |
| `GET` | `/v1/transport-key` | Exporta la clave pública de transporte (WPFE1) | clave generada en el arranque si `WPFE_KEY_MODE=generate` |
| `GET` | `/v1/attestation` | Documento de atestación NSM (base64) dentro de un enclave; `501` fuera | `?nonce=` opcional (`b64:` / `b64url:`) |

`certificate` es siempre el **sobre cifrado WPFE1** del bundle PEM
(clave+certificado del cliente), nunca el .p12 ni el PEM en claro.

## Configuración

**Signer:**

| Variable | Descripción |
|---|---|
| `WPFE_KEY_MODE` | `env` (por defecto) o `generate` (clave de transporte efímera generada al arrancar; la exporta `/v1/transport-key`) |
| `WPFE_PRIVATE_KEY` | Clave de transporte (PEM en línea o ruta) — modo `env` |
| `LISTEN` | `:8080` / `tcp:dir` (por defecto), o `vsock:puerto` dentro de un enclave |
| `NSM_DEVICE` | Dispositivo NSM (`/dev/nsm` dentro de un enclave; stub/local fuera) |

**Parent (puente host→enclave, binario `facturae-signer-parent`):**

| Variable | Descripción |
|---|---|
| `ENCLAVE_CID` | CID del enclave al que conectar por vsock |
| `INBOUND_LISTEN` | Dirección TCP de entrada en el host (p. ej. `127.0.0.1:8080`) |
| `RELAY_VSOCK_PORT` | Puerto vsock del relay de salida del signer |
| `ALLOWED_HOSTS` | Whitelist del relay `CONNECT host:port` (por defecto: sólo endpoints AEAT) |

El parent **no guarda secretos**: ni claves, ni certificados, ni blobs; sólo
enruta bytes (TLS de extremo a extremo hasta la AEAT).

## Seguridad en cinco líneas

1. El cliente sube su .p12 **una vez** a WordPress; éste guarda únicamente un
   sobre cifrado con la clave pública de transporte (WPFE1).
2. El signer descifra el sobre en memoria, firma y descarta; la clave de
   transporte vive en el proceso — o en RAM de enclave si `WPFE_KEY_MODE=generate`.
3. Dentro de un Nitro Enclave se expone `/v1/attestation` para que cualquier
   cliente verifique **qué imagen exacta** corre (`cmd/verify` lo automatiza
   contra `measurements.json` publicado con cada release).
4. El host nunca ve el tráfico de la AEAT: dentro del enclave la salida sale
   por un relay vsock con whitelist de hosts; el host sólo enruta bytes.
5. Nada de esto salva un WordPress comprometido *mientras sube* un .p12 — es
   el único momento en que el secreto transita su perímetro.

El análisis completo de amenazas vive en el sitio (página «Threat model» del
tema WPFacturaE).

## Uso rápido

```sh
make ci          # gofmt + vet + tests + build  (requisito de cualquier PR)
make build       # dist/signer + dist/facturae-signer-parent + dist/verify (+ SHA256SUMS)

# modo local sin claves reales (clave de transporte efímera):
WPFE_KEY_MODE=generate ./dist/signer &
curl -s localhost:8080/health        # ok

make e2e-local     # signer en docker (modo generate) + e2e por HTTP
make enclave-local # measurements simuladas para ejercitar cmd/verify
make enclave       # .eif + measurements REALES (sólo host EC2 con nitro-cli)
```

Verificación de un binario contra sus mediciones publicadas:

```sh
make verify DOC=attestation.json MEASUREMENTS=measurements.json KEY=pub.pem
```

Despliegue en enclave (bring-up, systemd, sonda KMS): **[README-enclave.md](README-enclave.md)**.

## Estructura

| Ruta | Rol |
|---|---|
| `main.go` | HTTP: enrutado, `/sign`, `/pdf`, `/verifactu/*`, `/v1/*` |
| `sign.go`, `bundle.go` | Firma XAdES + parsing/verificación del bundle PEM |
| `verifactu.go`, `verifactu_client.go` | Generación, firma y envío de registros |
| `pdf.go` | PDF VERI\*FACTU (incluye QR) |
| `attestation.go`, `nsm.go` | Documento de atestación y protocolo NSM |
| `config.go`, `listen.go` | Modos de clave, TCP/vsock |
| `parent/` | Puente host→enclave (vsock + relay `CONNECT` con whitelist) |
| `cmd/verify/` | Verificador de atestación + pinning de clave + nonce |
| `hack/` | Scripts de medición, e2e, bring-up y sonda KMS |
| `deploy/` | systemd, env de ejemplo, plantilla de política KMS |
| `Dockerfile`, `Dockerfile.enclave` | OCI con bases fijadas por digest / eif |
| `doc/` | Política de Firma oficial del formato Facturae (AOC) |

## Estado y límites

- Entorno **test** de AEAT/FACe y validadores AOC: verificados. Producción
  pendiente de certificados reales del emisor.
- Sin garantías de idoneidad; el uso fiscal es responsabilidad del operador.
- Firmar es un **oráculo**: quien puede llamar a `/sign` puede obtener
  firmas válidas. Protege la confidencialidad de la clave, no la autorización
  de negocio — eso sigue en tu perímetro (WordPress/red).

## Licencia

[MIT](LICENSE) © 2026 Alexey S. Kompaniets.

### Atribuciones

Las dependencias conservan sus propias licencias; los textos íntegros están
en [`licenses/`](licenses/):

**Directas:**

| Módulo | Licencia | Texto |
|---|---|---|
| `github.com/beevik/etree` | BSD-2-Clause | `licenses/LICENSE.etree` |
| `github.com/fxamacker/cbor/v2` | MIT | `licenses/LICENSE.cbor` |
| `github.com/go-pdf/fpdf` | MIT | `licenses/LICENSE.fpdf` |
| `github.com/invopop/xmldsig` | Apache-2.0 | `licenses/LICENSE.xmldsig` |
| `github.com/mdlayher/vsock` | MIT | `licenses/LICENSE.vsock` |
| `github.com/russellhaering/goxmldsig` | Apache-2.0 | `licenses/LICENSE.goxmldsig` |
| `github.com/skip2/go-qrcode` | MIT | `licenses/LICENSE.go-qrcode` |

**Transitivas enlazadas en los binarios:**

| Módulo | Licencia | Texto |
|---|---|---|
| `github.com/bahlo/generic-list-go` | BSD-3-Clause | `licenses/LICENSE.generic-list-go` |
| `github.com/buger/jsonparser` | MIT | `licenses/LICENSE.jsonparser` |
| `github.com/google/uuid` | BSD-3-Clause | `licenses/LICENSE.uuid` |
| `github.com/invopop/gobl` | Apache-2.0 (+NOTICE) | `licenses/LICENSE.gobl`, `licenses/NOTICE.gobl` |
| `github.com/invopop/jsonschema` | MIT | `licenses/LICENSE.jsonschema` |
| `github.com/jonboulle/clockwork` | Apache-2.0 | `licenses/LICENSE.clockwork` |
| `github.com/mdlayher/socket` | MIT | `licenses/LICENSE.socket` |
| `github.com/pb33f/ordered-map/v2` | Apache-2.0 | `licenses/LICENSE.ordered-map` |
| `github.com/x448/float16` | MIT | `licenses/LICENSE.float16` |
| `go.yaml.in/yaml/v4` | MIT / Apache-2.0 (dual) | `licenses/LICENSE.yaml-v4` |
| `golang.org/x/crypto`, `x/net`, `x/sync`, `x/sys` | BSD-3-Clause (Go Authors) | `licenses/LICENSE.golang-x-*` |
| `software.sslmate.com/src/go-pkcs12` | BSD-3-Clause | `licenses/LICENSE.go-pkcs12` |

`doc/Politica_Firma_formato_facturae_3_1.pdf` es el documento oficial de
política de firma de la [AOC](https://www.aoc.es) (Facetric), reproducido
como referencia pública; no forma parte del código bajo MIT.

## Ver también

- [README-enclave.md](README-enclave.md) — despliegue en AWS Nitro Enclave,
  medición, verificación y sonda de política KMS.
