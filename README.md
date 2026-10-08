# ExternalFEO backend for Render

Node.js 20+, Express and PostgreSQL. This package supports the currently identified device-auth endpoints and the legacy encrypted license endpoints. Because the IPA executable is obfuscated, the exact full request inventory still needs to be confirmed from Render request logs during a real activation. Unknown routes are logged as method + path (never request bodies or tokens) and return JSON 404 to make mismatches diagnosable.

## Render environment variables

Required:
- `DATABASE_URL`: Render PostgreSQL connection URL
- `ADMIN_TOKEN`: strong secret used by the license manager

Recommended:
- `APP_ID=external.com`
- `PACKAGE_ID=External`
- `CRYPT_SECRET` and `WIRE_SECRET`: must match the legacy client if the legacy encrypted protocol is used
- `MAX_CLOCK_SKEW=300`
- `DOWNLOAD_ORIGIN`: optional trusted upstream base URL for legacy files. Local files in `downloads/` are served first; missing files can fall back to this origin.
- `MOD_CATALOG_JSON`: optional JSON string with per-game catalogue data. Example: `{"ffth":{"aim":{"Aim Peito":"/download/aim-peito.bin"},"visual":{},"chams_file":"","chams_json":{}}}`. This is illustrative; use the exact schema the app expects and ensure the referenced file exists.

## Identified routes

- `POST /api/device/register` — expects JSON `{ "device_uuid": "..." }`; returns a bearer token.
- `POST /api/device/activate` — expects `Authorization: Bearer <token>` and JSON containing `license_key`; binds the license to the registered device.
- `GET /api/device/mods/:gameKey` — authenticated; returns the matching object from `MOD_CATALOG_JSON`, or an empty scaffold if not configured.
- `POST /external/api/server.php` and `POST /a1234567` — legacy encrypted license protocol.
- `/admin` — browser license manager; protect it with `ADMIN_TOKEN`.
- `POST /admin/licenses` with Bearer `ADMIN_TOKEN` — create/update a license, JSON `{ "license_key": "...", "days": 30 }`.
- `GET /health` — health/database check.

## Deploy

1. Upload this folder to the GitHub repository connected to Render.
2. Ensure the start command is `npm start` and Node is 20 or newer.
3. Set `DATABASE_URL` to the Render PostgreSQL URL and `ADMIN_TOKEN` to a long random secret.
4. Deploy, then check `/health`.
5. Put the real assets in `downloads/` with the expected filenames and test `/download/<filename>`.
6. Configure `MOD_CATALOG_JSON` in Render to reference those real files, then redeploy.
7. Trigger one activation attempt and inspect Render logs for `http_request` lines. If `unhandled_route` appears, its method/path identifies an additional route that must be implemented.

## Important limitations

This server cannot make the IPA contact Render by itself. The IPA must have its base URL changed to `https://externalfeo.onrender.com`, and its TLS pin must match the actual pinning algorithm in that binary. Local downloads do not require `DOWNLOAD_ORIGIN`; a missing local file returns 404 unless a trusted upstream fallback is configured. A successful `/` or `/health` check does not prove activation or injection works end-to-end.
