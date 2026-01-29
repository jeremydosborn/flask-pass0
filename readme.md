# flask-pass0

Passwordless auth primitives for Flask.

**Status: Untested refactor, API will change**

## What's here

- `Pass0` - Main class, session helpers (login, logout, is_authenticated)
- `Passkey` - WebAuthn registration/authentication
- `MagicLink` - Email token generation/verification
- `TOTP` - 2FA setup/verification with backup codes
- `SQLAlchemyStorageAdapter` - Postgres/SQLite/MySQL

## License

Apache 2.0 - See LICENSE