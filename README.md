# External Auth compatible server

Base URL intended for the IPA:

`https://externalfeo.onrender.com`

License endpoint:

`POST /external/api/server.php`

Admin API uses `Authorization: Bearer $ADMIN_TOKEN`.

## Render setup

1. Create a PostgreSQL database on Render.
2. Create the web service from this directory/repository.
3. Set `DATABASE_URL` to the Postgres internal/external connection string.
4. Set a strong random `ADMIN_TOKEN`.
5. Deploy.

The app creates the `licenses` table automatically.

## Create a license

`POST /admin/licenses`

JSON:

`{"license_key":"EXT-ABC-123","days":30}`

## Operational notes

The server intentionally preserves the protocol used by the supplied IPA: encrypted JSON payloads, rolling XOR key derivation, status strings, package/app checks, device binding and expiration.
