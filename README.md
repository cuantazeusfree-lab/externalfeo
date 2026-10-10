# ExternalFEO Auth — starter

Backend inicial de licencias de 30 días con panel web y persistencia SQL. Está preparado para desplegarse en Render.

## Incluye
- Panel privado `/` (usuario/contraseña definidos por variables de entorno).
- Generar licencias `FEO-XXXXX-XXXXX-XXXXX-XXXXX`.
- Activación de 30 días desde el primer uso.
- Vinculación a un identificador de dispositivo; la misma licencia no se activa en otro dispositivo.
- Validación, expiración y revocación.
- `GET /health`.
- `POST /api/licenses/activate` y `POST /api/licenses/validate`.
- API administrativa con `X-Admin-Token: <ADMIN_TOKEN>` o `Authorization: Bearer <ADMIN_TOKEN>`.
- Hash de licencias y hash HMAC del identificador del dispositivo; la licencia completa solo se muestra al generarla.

## Despliegue en Render
1. Sube estos archivos a un repositorio privado de GitHub.
2. En Render, crea un Blueprint desde el repositorio y revisa `render.yaml`.
3. Configura `ADMIN_PASSWORD` y `ADMIN_TOKEN` como secretos largos y únicos. No los publiques ni los pongas en la app iOS.
4. Despliega y comprueba `https://TU-DOMINIO/health`.
5. Entra al dominio para abrir el panel de administración.

`render.yaml` crea una base de datos de pago. Si ya tienes PostgreSQL en Render, puedes quitar el bloque `databases` y configurar `DATABASE_URL` con la URL interna de esa base.

## Prueba local
```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
export ADMIN_USERNAME=admin
export ADMIN_PASSWORD='use-a-long-unique-password'
export ADMIN_TOKEN='use-a-long-random-token'
export SESSION_SECRET='another-long-random-secret'
export DEVICE_HASH_SECRET='another-long-random-device-secret'
uvicorn app:app --reload
```
Panel: `http://127.0.0.1:8000`. Health: `http://127.0.0.1:8000/health`.

## Ejemplo de uso de la API
Generar:
```bash
curl -X POST http://127.0.0.1:8000/api/admin/licenses/generate \
  -H 'Content-Type: application/json' -H 'X-Admin-Token: YOUR_ADMIN_TOKEN' \
  -d '{"count":2,"label":"cliente"}'
```
Activar:
```bash
curl -X POST http://127.0.0.1:8000/api/licenses/activate \
  -H 'Content-Type: application/json' \
  -d '{"license_key":"FEO-XXXXX-XXXXX-XXXXX-XXXXX","device_id":"DEVICE-IDENTIFIER"}'
```

## Importante sobre compatibilidad con la IPA
Este repositorio implementa un contrato de licencias nuevo y documentado; **no demuestra compatibilidad 100% con una IPA ya compilada**. Para hacer que una app existente lo consuma, hace falta identificar y adaptar los contratos reales del cliente (paths, nombres de campos, códigos HTTP, respuestas y, si corresponde, firma/nonce). No debe cambiarse el servidor para emular mecanismos de exploit o eludir controles de seguridad. La activación aquí es un esquema genérico de licencia; el `device_id` debe proceder de un identificador que la app esté autorizada a usar.
