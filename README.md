# ExternalFEO backend for the current PoloniumExternal IPA

Node.js + Express + PostgreSQL service for the IPA's current device-auth protocol.

## Render environment

- `DATABASE_URL`: Render PostgreSQL internal connection URL
- `ADMIN_TOKEN`: secret for the license manager
- `PORT`: supplied automatically by Render

The older `APP_ID`, `PACKAGE_ID`, `CRYPT_SECRET`, and `WIRE_SECRET` variables are retained only for the legacy routes; the current IPA endpoints below do not use them.

## Current IPA endpoints

1. `POST /api/device/register`
   - JSON body: `{"device_uuid":"..."}`
   - Returns: `{"ok":true,"token":"..."}`
2. `POST /api/device/activate`
   - Header: `Authorization: Bearer <token>`
   - JSON fields: `license_key`, `device_model`, `ios_version`, `device_fingerprint`, `hwid`
   - Returns `{"ok":true,...}` on activation or `{"ok":false,"code":"not_found|banned|expired|other_device|validation_error|maintenance",...}` on failure.
3. `GET /api/device/mods/ffth` or `GET /api/device/mods/ffmax`
   - Header: `Authorization: Bearer <token>`
   - Returns an empty catalogue scaffold (`aim`, `visual`, `chams_file`, `chams_json`) until mod assets/catalogue entries are configured.

## License manager

Open `/admin` on the deployed service and enter the configured `ADMIN_TOKEN`. The manager can generate 30-day license keys and supports listing, banning, and unbinding licenses.

## Important TLS pin note

The IPA's field is named `spkiPinB64`, but the inspected code does **not** hash DER SubjectPublicKeyInfo: it calls `SecTrustCopyKey`, `SecKeyCopyExternalRepresentation`, SHA-256, then Base64. The comparison value currently embedded in this IPA is `hDWhdFvljKFrz1ZoyXbdbjzTkP2d7991FIsYpaTcfLw=`.

The supplied `onrender-com.pem` has issuer `ReasonLabs / RAV Endpoint Protection CA 3`, indicating TLS interception. Its key hash is not the correct pin for the public Render endpoint. Do not replace the embedded value with a hash from that PEM. Obtain the real certificate/public key from a network without TLS interception, then compute SHA-256/Base64 over the key bytes in the same format returned by Apple's `SecKeyCopyExternalRepresentation` (RSA: DER PKCS#1 public key; EC: uncompressed X9.63 point).
