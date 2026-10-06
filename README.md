# External Auth Server

Express + PostgreSQL backend compatible with the External license/auth protocol.

## Render

Set these environment variables:

- `DATABASE_URL` = Render PostgreSQL Internal Database URL
- `ADMIN_TOKEN` = a secret token used for license administration
- `CRYPT_SECRET` = `Fluck2020@Zexis`
- `WIRE_SECRET` = `@IamGayBecauseYouAreSexy`
- `APP_ID` = `external.com`
- `PACKAGE_ID` = `External`
- `MAX_CLOCK_SKEW` = `300`

The existing client endpoint remains:

`POST /external/api/server.php`

## License management

Open:

`https://externalfeo.onrender.com/admin`

Enter the same `ADMIN_TOKEN` configured in Render.

The panel can:

- Generate a new random key valid for exactly 30 days.
- List existing licenses.
- Unbind a license from its device.
- Ban a license.

The license API and authentication protocol are unchanged.
