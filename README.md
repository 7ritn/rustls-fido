# rustls-fido

This cargo package provides the FIDO2 logic for providing client authentication to rustls.
Furthermore, two binary applications for registration and authentication are provided.
Especially the registration can be used, if a protocol only allows authentication.

## Registration
The `register` binary creates a new resident key on the attached USB FIDO2 token. Server state will be saved in the SQLite database.

Environmental variables are used to specify the configuration:

| Variable Name            | Description                                   | Default Value | Example Value       |
|--------------------------|-----------------------------------------------|---------------|---------------------|
| `FIDO_RP_ID`             | FIDO Relying Party ID                         | `localhost`   | `example.com`       |
| `FIDO_RP_NAME`           | FIDO Relying Party Name                       | `localhost`   | `Example Inc.`      |
| `FIDO_USER_NAME `        | FIDO username for authentication/registration | `user`        | `alice`             |
| `FIDO_USER_DISPLAY_NAME` | FIDO display name                             | `User`        | `Alice Smith`       |
| `FIDO_TIMEOUT`           | FIDO timeout in milliseconds                  | `6000`        | `30000`             |
| `FIDO_DB_PATH`           | Path to the FIDO database file                | `./fido.db3`  | `/var/lib/fido.db3` |
| `FIDO_DEVICE_PIN`        | FIDO PIN for authentication                   | `1234`        | `5678`              |