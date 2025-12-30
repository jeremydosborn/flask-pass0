# flask-pass0

Lightweight passwordless authentication for Flask with magic links and two-factor authentication.

Alpha version - API may change

WARNING: InMemoryStorageAdapter is for development only. Use SQLAlchemyStorageAdapter or implement a custom adapter for production.

## Features

- Magic Link Authentication - Email-based passwordless login
- Two-Factor Authentication (2FA) - TOTP support with QR code generation and backup codes
- Flexible Storage - Works with in-memory dict, SQLAlchemy, or custom backends
- Session Management - Secure session handling with regeneration
- API-First Design - Returns JSON, configurable for template-based apps

## Quick Start

```python
from flask import Flask
from flask_pass0 import Pass0
from flask_pass0.storage import SQLAlchemyStorageAdapter

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key'
app.config['PASS0_2FA_ENABLED'] = True
app.config['PASS0_2FA_VERIFY_ROUTE'] = 'verify_2fa_page'  # Required if 2FA enabled

storage = SQLAlchemyStorageAdapter(user_model=User, session=db.session, secret_key=app.config['SECRET_KEY'])
pass0 = Pass0(app, storage_adapter=storage)
```

## Installation

```bash
pip install flask-pass0
```

Optional dependencies:

```bash
pip install flask-pass0[all]  # All features
pip install flask-pass0[2fa]  # 2FA only
pip install flask-pass0[email]  # Email support
```

## Configuration

```python
app.config['PASS0_2FA_ENABLED'] = True
app.config['PASS0_2FA_VERIFY_ROUTE'] = 'your_2fa_route'  # Required when 2FA enabled
app.config['PASS0_DEV_MODE'] = False  # Logs magic links instead of emailing
```

## License

MIT