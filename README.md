# External Backend

Backend reconstruido para el protocolo de licencia observado en la IPA suministrada.

## Contrato

La aplicación usa `LicenseAPIURL` como URL base y realiza estas solicitudes JSON.

### Activación

POST `/v1/activations`

```json
{"key":"TU-LICENCIA","publicKey":"BASE64"}
```

Respuesta:

```json
{"activationId":"..."}
```

### Challenge

POST `/v1/challenges`

```json
{"activationId":"..."}
```

Respuesta:

```json
{"challengeId":"...","nonce":"BASE64"}
```

### Verificación

POST `/v1/verifications`

```json
{"activationId":"...","challengeId":"...","signature":"BASE64"}
```

Respuesta:

```json
{"status":"ACTIVE"}
```

## Criptografía

La IPA crea una clave EC P-256 en Secure Enclave. La representación pública enviada al backend es Base64 de la representación externa de `SecKey`.

El `nonce` se devuelve en Base64. La IPA lo decodifica y firma los bytes con `ECDSA + SHA-256`. La firma se manda en Base64 y se verifica en el servidor.

## Ejecutar

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --host 0.0.0.0 --port 8000
```

Crear licencia:

```bash
python3 scripts/create_license.py --days 365
```

## Conectar la IPA

La IPA contiene `LicenseAPIURL = https://proxy.vin`.

Si ese dominio es tuyo, puedes apuntarlo al servidor y conservar la IPA sin cambiar esa URL.

Si no controlas ese dominio, habrá que cambiar `LicenseAPIURL` dentro de la IPA y volver a firmarla.

## Producción

Usa HTTPS. Para producción también recomiendo PostgreSQL, rate limiting, logs, backups y un panel para crear/revocar licencias.

Este backend implementa el protocolo compatible; las reglas de negocio de licencias quedan bajo nuestro control.
