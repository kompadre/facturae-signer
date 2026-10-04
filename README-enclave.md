# facturae-signer en Nitro Enclave — runbook (CD/CI + TEE)

Estado: **fases 1–4 de código/listas localmente**; bring-up en EC2 pendiente
(primer run real con `nitro-cli`). Objetivo: el signer funciona en un TEE y
**la infraestructura (host/root/cloud) no puede descifrar los datos de los
clientes** — la clave de transporte vive sólo en la RAM del enclave.

## Modelo de confianza

1. **Clave generada en el enclave** (`WPFE_KEY_MODE=generate`): RSA-2048 en
   memoria al arrancar; nunca se escribe en disco ni sale de la RAM
   aislada. Sólo ese enclave instance puede abrir los blobs WPFE1 que
   cifra WordPress.
2. **Attestation doc con la pública enlazada**: `GET /v1/attestation`
   devuelve el doc del NSM con la SPKI en `public_key` + `user_data` =
   `facturae-signer/<versión>`; cualquiera verifica PCR0/PCR2 contra las
   mediciones publicadas del release y la clave servida en
   `GET /v1/transport-key`.
3. **Parent sin secretos** (`parent/`): puente WordPress→enclave (TCP →
   vsock) y relay de salida con whitelist exacta `host:puerto` (los 4
   endpoints AEAT). El mTLS con la AEAT es de extremo a extremo en el
   enclave; el parent sólo retransmite bytes.
4. **Imagen medida**: bases fijadas por digest + `VERSION` en ldflags ⇒
   PCR0/PCR2 identifican el binario exacto. Mediciones publicadas por
   release junto al artefacto.

## Bucle local (sin hardware Nitro)

```sh
make ci             # fmt + vet + test + build (dist/)
make image          # imagen OCI (bases por digest)
make e2e-local      # docker en modo generate + sign por HTTP (verde ✓)
make enclave-local  # measurements.json SIMULADOS (sha256 del binario)
make verify DOC=… MEASUREMENTS=measurements.json   # cmd/verify
```

`nitro-cli` **no existe en modo local**: `run-enclave` exige el driver
`nitro_enclaves` sobre hardware Nitro (EC2 con enclaves habilitadas; ni
Debian ni una VM KVM local cualquiera sirven). Por eso `make enclave` y
`make e2e` están puerteados detrás de un chequeo con mensaje claro.

## Bring-up en EC2

```sh
# 1. nitro-cli instalado + /dev/nitro_enclaves + hugepages (ver AWS docs)
make build
hack/enclave-up.sh [--debug] [--cpu 2] [--memory 256] [--root aws-root.pem]
```

El script: `make enclave` (`.eif` + measurements reales) → `run-enclave`
→ parent con `ENCLAVE_CID` → health → transport-key → attestation con
nonce → `cmd/verify` → imprime la `signing_url` para WordPress.

- **`--debug`**: `nitro-cli run-enclave --debug-mode` + consola en vivo
  (`nitro-cli console --enclave-id <id>`) para ver el stdout del signer
  dentro del enclave. **En debug el NSM emite PCR0/PCR2 a cero** en el
  attestation doc: `cmd/verify` lo acepta sólo con measurements de modo
  `nitro-debug` y avisa con mayúsculas. Jamás confiar en un doc de debug.
- **Release**: sin `--debug`; measurements reales (`hack/measure.sh`, que
  corre un enclave *sin* debug para leer PCRs no nulos) y verify en modo
  `nitro`.

systemd: `deploy/systemd/facturae-signer-parent.service` +
`deploy/enclave.env.example` (ENCLAVE_CID, puertos, whitelist). El parent
no lleva secretos: sólo `ENCLAVE_CID` y whitelist.

## Rotación de clave (v1)

La clave del enclave es efímera: al redesplegar/reiniciar, la pública
cambia, los blobs antiguos no se abren y el signer responde con
«¿rotación de la clave? Vuelve a subir el certificado en Ajustes».
Operación: pegar de nuevo el PEM de `/v1/transport-key` en Ajustes →
subir otra vez el .p12 (se re-cifra contra la clave nueva). Continuidad
de clave con KMS+attestación = v2.

## cmd/verify

```sh
go run ./cmd/verify -doc doc.json -measurements measurements.json \
  [-key pubkey.pem] [-nonce b64:…] [-binary bin] [-root aws-root.pem]
```

- modos de measurements: `nitro` (pcr0/pcr2 hex), `simulated`
  (sha256 del binario; sólo el bucle local), `nitro-debug` (ceros + aviso).
- `-doc` acepta CBOR crudo, base64 o el wrapper JSON del endpoint.
- `-nonce`: `b64:`/`b64url:` o crudo (prefijos explícitos: sin ambigüedad).
- `-root` (opcional): cadena certificate/cabundle → raíz + firma del doc
  sobre las codificaciones canónicas RFC7049 y RFC8949 (mejor esfuerzo).

## CD/CI

Targets pensados para cualquier runner (GitHub Actions o vsrv1 = capa
fina sobre `make`): `ci`, `image`, `image-enclave`, `enclave` (EC2),
`enclave-local`, `e2e-local`, `verify`. Artefactos: `dist/SHA256SUMS`,
imagen, `measurements.json` (real) por release. `.gitignore` excluye
`dist/` y `measurements.json` (los reales se publican como artefacto).


## S1 — sonda de contrato de sellado (KMS)

Antes de implementar el sellado de la clave de transporte (S2 / arquitectura
D′), la sonda confirma empíricamente en tu cuenta qué exige realmente KMS:

```sh
nitro-cli-config -i -m 512 -t 4        # una vez por host
hack/kms-probe.sh --region <tu-region> [--keep]
```

Con una key desechable y dos enclaves reales (imagen buena + imagen
atacante = imagen buena + capa ENV que cambia la medición) mide:

| Pregunta | Esperado | Si sale distinto |
|---|---|---|
| P1 plain `Decrypt` sin `Recipient` | denegado | **BAIL**: sin sellado; modo efímero v1 |
| P2 `Decrypt(Recipient=doc propio)` | `CiphertextForRecipient`, `Plaintext` vacío | revisar ortografía (P4) / permisos |
| P3 `Recipient` con doc de imagen atacante | denegado | **INV-2 no existe** ⇒ arquitectura D (sealer off-host) |
| P4 ortografía de condición + pin PCR2 | informa (`ImageSha384` documentada; `PCR0` = plantilla alternativa) | elegir la que acepte |

Resultado esperado (documentado en AWS: *Condition keys for Nitro Enclaves* —
«AWS KMS compares the attestation document to the values in these condition
keys»): P1/P2/P3 = SÍ ⇒ **D′**: plantilla `deploy/kms-policy.json`
(sustituir ACCOUNT, roles y los dos hex con `measurements.json` del
release) + `WPFE_KEY_MODE=seal` en S2.

La key de la sonda se borra con `schedule-key-deletion` (ventana mínima de
7 días de KMS) al salir; `--keep` la conserva para iterar.

## Notas / pendientes

- **Gramine** (mencionado como alternativa local): pivota a SGX, no a
  Nitro; su modo directo no aporta TEE real. Lo dejamos como opción sólo
  si se quiere una ruta SGX además de Nitro.
- Permisos de `/dev/vsock` y `/dev/nsm` como `nobody` en la imagen de
  enclave: comprobar en el primer e2e de EC2 (si EPERM → `USER root` en
  `Dockerfile.enclave`, comentado allí).
- `measurements` por release: el `VERSION` (ldflags) cambia el binario
  ⇒ PCR distinto por release; publicar siempre con el tag.
