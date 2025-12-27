# flask-pass0

Lightweight passwordless authentication for Flask with magic links, two-factor authentication, and device binding.

Alpha version

## Features

- **Magic Link Authentication** - Email-based passwordless login
- **Two-Factor Authentication (2FA)** - TOTP support with QR code generation
- **Device Binding** - Trust and manage user devices
- **Flexible Storage** - Works with in-memory dict, SQLAlchemy, or custom backends
- **Session Management** - Secure session handling

## Quick Start

```python
from flask import Flask
from flask_pass0 import FlaskPass0Auth

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key'

auth = FlaskPass0Auth(
    app=app,
    magic_link={'enabled': True},
    two_factor={'enabled': True}
)
```

## Installation

```bash
pip install flask-pass0
```

Optional dependencies:
```bash
pip install flask-pass0[all]  # All features
pip install flask-pass0[twofa]  # 2FA only
pip install flask-pass0[email]  # Email support
```

## License

MIT
