# facturae-signer — despliegue en VPS / mismo host

Estado del **downscale**: la firma ya no necesita Nitro Enclave. El mismo
binario sirve en tres formas, y éste es el runbook para las dos primeras
(el modo enclave queda documentado en `README-enclave.md` y **parado**).

| Forma | Dónde | Transporte |
|---|---|---|
| **A. Mismo host** que WordPress | `wpfe-sign` + socket unix | sin red por medio |
| **B. VPS separado** | `signer` + nginx/TLS | HTTPS + envoltorio WPFE1 |
| C. Enclave Nitro (parado) | imagen `Dockerfile.enclave` | vsock + attestation NSM |

---

## 1. Modelo de confianza (qué protege qué)

```
machine_secret (/etc/machine-id [· /etc/facturae-signer.salt])
        │  HKDF-SHA256, salt = provision_salt, info = "…/master/v1|" ‖ SPKI host
        ▼
   master ──AES-256-GCM──► keystore.bin  (clave de transporte RSA-2048)
                                 ▲
   identidad del host (host.key + host.cert) firma el VÍNCULO:
       "wpfe-binding/v1" ‖ SPKI(transporte) ‖ SPKI(host) ‖ issued_at
```

- **Clave de transporte**: se genera una vez (`wpfe-sign init`), publicada en
  `/v1/transport-key?format=json` o `wpfe-sign pubkey --json`. Toda petición
  de negocio viaja envuelta en WPFE1 (AES-256-GCM con la clave envuelta a esa
  pública): el bundle del usuario —que contiene **su clave privada de
  firma**— nunca cruza el canal en claro, ni por red ni por tubería.
- **Vínculo + huella**: el plugin fija `host_fingerprint` en el primer
  contacto (TOFU) y lo verifica en cada llamada. Un `/etc/hosts` manipulado
  sirve otra identidad ⇒ huella distinta ⇒ se rechaza. Esto funciona **sin
  TLS**, que es lo que permite el modo A.
- **Firma en claro en las respuestas**: por defecto `WPFE_SEAL_RESPONSES=0`
  (el XAdES ya autentica el XML de vuelta); si lo activas, la respuesta se
  sella con la MISMA clave AES de la petición y WordPress la abre sin tener
  pareja propia.

## 2. Provisionamiento (una vez)

```bash
useradd --system --home-dir /var/lib/facturae-signer --shell /usr/sbin/nologin facturae-signer
install -d -o facturae-signer -g facturae-signer -m 0700 /var/lib/facturae-signer
install -m 0755 dist/wpfe-sign /usr/local/bin/wpfe-sign     # = dist/signer

sudo -u facturae-signer /usr/local/bin/wpfe-sign init
#   modo: persistent
#   host_fingerprint: sha256:…      ← pégalo en FacturaE → Ajustes → Huella del signer
#   keystore: /var/lib/facturae-signer/keystore.bin (0640)
```

Opcional, segundo factor (ver §5): `WPFE_MASTER_SALT_FILE`.

En WordPress: Ajustes → **Canal con el signer** = `Automático` (o `Local`);
la clave pública se pega con `wpfe-sign pubkey` o se trae sola en el primer
envío (modo vínculo). `signing_url` sólo hace falta en el modo red.

## 3. Despliegue A — mismo host (socket)

```bash
cp deploy/systemd/facturae-signer.socket /etc/systemd/system/
cp deploy/systemd/facturae-signer.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now facturae-signer.socket facturae-signer.service
wpfe-sign doctor        # 0 = se puede firmar en este host
```

- El socket lo crea la unidad `.socket` con `SocketMode=0660`,
  `SocketUser=root`, `SocketGroup=www-data`: habla el plugin, nadie más.
  (Si prefieres el servicio como dueño: `SocketUser=facturae-signer` +
  `SocketGroup=www-data`.)
- Con activación, el servicio ni toca el fichero (ni lo desvincula); sin
  activación, el binario borra sockets huérfanos, escucha y aplica
  `WPFE_SOCKET_MODE` (0660 por defecto) + `WPFE_SOCKET_UID/GID`.
- El plugin detecta el socket solo (`Automático`); si no existe, cae al binario.

## 4. Despliegue B — VPS separado (nginx + TLS)

```ini
# facturae-signer.service (variante)
Environment=LISTEN=:8081
Environment=WPFE_REQUIRE_ENVELOPE=1     # exige WPFE1 en toda entrada
```

nginx: `proxy_pass http://127.0.0.1:8081;` con certificado Let's Encrypt.
`WPFE_HOST_CERT/WPFE_HOST_KEY` pueden apuntar al par TLS si quieres cruzar
el vínculo con el certificado del sitio; **por defecto no**: el par TLS rota
cada ~60-90 días y la identidad del host debe ser estable (si la rota, el
signer re-envuelve el keystore al arrancar y conserva la misma clave de
transporte — los clientes no se enteran).

WordPress: `signing_url = https://firmas.example.com/sign`, canal `Red`.

## 5. En reposo: qué gana cada capa (y qué no)

| Archivo | Permisos | Protege contra |
|---|---|---|
| `keystore.bin` | 0640 root:facturae-signer | copia a otra máquina (el master cambia ⇒ rehúsa firmar) |
| `host.key` | 0600 facturae-signer | falsificación del vínculo |
| `/etc/facturae-signer.salt` | **0440 root:facturae-signer** | clon byte-a-byte del disco (§ siguiente) |
| `WPFE_DATA_DIR` | 0700 | lectura por otros usuarios |

> El `0400 root:root` propuesto para el salt sólo funciona si el servicio
> corre como root; con `User=facturae-signer` legibilidad = `0440` con grupo
> del servicio. El signer falla al arrancar si el salt es obligatorio y no
> se puede leer (falla cerrado, no en silencio).

**Salto idéntico de clon**: `machine-id` viaja en el disco clonado, así que
un clon byte-a-byte *del mismo host* deriva el mismo master. Con
`WPFE_MASTER_SALT_FILE` definido (modo estricto) el salt deja de estar en el
volumen copiado y el clon no abre nada. TPMe/vTPM no existen en el VPS barato:
queda como futura mejora.

**Limites conocidos**: root local en el host = fin del juego (lee en RAM);
`www-data` puede *usar* la clave pero no extraerla (no hay subcomando de
exportación); `/health` queda en claro a propósito (sonda, cero datos).

## 6. Rotaciones

| Qué rota | Efecto | Acción |
|---|---|---|
| Certificado Let's Encrypt (~90 d) | el SPKI del host cambia | ninguna: el signer re-envuelve el keystore al arrancar y re-firma el vínculo |
| Keystore/clave de transporte | imposible sin host secret | — |
| Identidad del host (`host.key`) | huella nueva | el plugin rechaza hasta que confirmes la huella nueva en Ajustes |
| Certificado de firma del usuario (P12) | — | se sube en WordPress: se abre ALLÍ, se envía el bundle PEM cifrado (no hay contraseña en el signer) |

## 7. Diagnóstico

```bash
wpfe-sign doctor      # estado; sale != 0 si aquí no se puede firmar
wpfe-sign pubkey --json   # documento de vínculo (lo que verifica el cliente)
curl --unix-socket /run/facturae-signer/signer.sock http://localhost/v1/info
```

Errores típicos al arrancar: `keystore: no se puede abrir en este host…`
(machine salt distinto ⇒ clon o máquina nueva) y
`keystore: no se pudo leer el salt externo…` (permisos del §5).

## 8. Comandos

```
wpfe-sign serve                 sirve (socket si hay activación/WPFE_SOCKET)
wpfe-sign init                  alta idempotente (keystore + identidad)
wpfe-sign doctor                diagnóstico (0 = se puede firmar)
wpfe-sign pubkey [--json]       clave pública / documento de vínculo
wpfe-sign sign|pdf|verifactu-alta|verifactu-consulta < body.json
```

Salidas de los comandos de petición: JSON en stdout (idéntico al endpoint);
códigos 0/2/3/4 → 200/400/503/502 en el contrato con el plugin.
