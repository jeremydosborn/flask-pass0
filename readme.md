# flask-pass0

Passwordless authentication for Flask with passkeys (WebAuthn), magic links, and optional 2FA.

**WIP: API may change**

**Experimenting with identity-less/graduated auth, results may vary in near-term**

## Design

**Choose your primary auth method**: Magic links OR passkeys  
**Add optional 2FA**: TOTP + backup codes layer on top

Flask-Pass0 provides JSON API routes via Blueprint (`/auth/*`). You build your own UI and call the endpoints.

**Storage adapter pattern**: Plug in any backend (in-memory for dev only, SQLAlchemy for production, or custom).

## Features

- **Magic Links** - Tokenized email login
- **Passkeys (WebAuthn)** - Biometric/hardware key auth
- **Two-Factor Auth** - TOTP + backup codes (optional layer)
- **Flexible Storage** - InMemory (dev only), SQLAlchemy, or custom
- **Session Management** - Secure sessions with auto-expiry

## Installation
```bash
pip install flask-pass0        # Core (both auth methods available)
pip install flask-pass0[all]   # All features (2FA + email + SQLAlchemy)
```

## Quick Start
```python
from flask import Flask
from flask_pass0 import Pass0
from flask_pass0.storage import SQLAlchemyStorageAdapter

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key'

# Choose primary auth method
app.config['PASS0_PRIMARY_AUTH'] = 'magic_link'  # or 'passkey'

# For passkeys (required if PRIMARY_AUTH = 'passkey')
app.config['PASS0_RP_ID'] = 'localhost'
app.config['PASS0_RP_NAME'] = 'My App'

# Optional: Add 2FA layer
app.config['PASS0_2FA_ENABLED'] = True
app.config['PASS0_2FA_VERIFY_ROUTE'] = 'verify_2fa'  # Your UI route

storage = SQLAlchemyStorageAdapter(user_model=User, session=db.session)
pass0 = Pass0(app, storage_adapter=storage)

@app.route('/dashboard')
@pass0.login_required
def dashboard():
    user = pass0.get_current_user()
    return f"Hello {user['email']}"
```

## Configuration

### Core (Required)
```python
app.config['SECRET_KEY'] = 'your-secret-key'
app.config['PASS0_PRIMARY_AUTH'] = 'magic_link'   # or 'passkey'
```

### Passkey Settings (required if PRIMARY_AUTH = 'passkey')
```python
app.config['PASS0_RP_ID'] = 'localhost'           # Your domain
app.config['PASS0_RP_NAME'] = 'My App'            # Display name
app.config['PASS0_ORIGIN'] = 'http://localhost:5000'  # Optional
```

### Optional Two-Factor Authentication
```python
app.config['PASS0_2FA_ENABLED'] = True            # Enable 2FA support
app.config['PASS0_2FA_VERIFY_ROUTE'] = 'verify_2fa'  # Required if enabled
app.config['PASS0_2FA_REQUIRED'] = False          # Force all users to enable 2FA
app.config['PASS0_TOTP_ISSUER'] = 'My App'        # TOTP issuer name
```

### Other Settings
```python
# Sessions
app.config['PASS0_SESSION_DURATION'] = 86400      # Seconds (default: 24h)
app.config['PASS0_REDIRECT_URL'] = '/'            # Post-login redirect
app.config['PASS0_LOGIN_URL'] = '/login'          # Your login page

# Magic Links
app.config['PASS0_TOKEN_EXPIRY'] = 10             # Minutes (default: 10)
app.config['PASS0_DEV_MODE'] = False              # Log links instead of emailing

# Email (for magic links)
app.config['MAIL_SERVER'] = 'smtp.example.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'user@example.com'
app.config['MAIL_PASSWORD'] = 'password'
app.config['MAIL_DEFAULT_SENDER'] = 'noreply@example.com'
```

## API Routes

All routes on `/auth/*` blueprint:

**Magic Link:**
- `POST /auth/request-magic-link` - Request magic link
- `GET /auth/verify/<token>` - Verify token

**Passkey:**
- `POST /auth/passkey/register/options` - Get registration options
- `POST /auth/passkey/register/verify` - Complete registration
- `POST /auth/passkey/login/options` - Get login options
- `POST /auth/passkey/login/verify` - Complete login
- `GET /auth/passkeys` - List user's passkeys
- `DELETE /auth/passkeys/<int:passkey_id>` - Revoke passkey

**2FA (when enabled):**
- `GET/POST /auth/2fa/setup` - Setup TOTP
- `GET/POST /auth/2fa/verify` - Verify code
- `POST /auth/2fa/disable` - Disable 2FA
- `GET/POST /auth/2fa/backup-codes` - Regenerate codes

**Session:**
- `GET /auth/logout` - Clear session
- `GET /auth/login` - Redirect to login UI
```

## License

MIT OR Apache-2.0

**WARNING:** Never use `InMemoryStorageAdapter` in production.