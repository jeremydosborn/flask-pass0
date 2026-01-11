"""
Flask-Pass0 Storage Adapters with 2FA, Device Binding
"""

import hmac
import hashlib
import threading
import secrets
from abc import ABC, abstractmethod
from datetime import datetime, timedelta, timezone
from cryptography.fernet import Fernet



class StorageAdapter(ABC):
    """Extended base storage adapter interface"""
    
    @abstractmethod
    def get_user_by_email(self, email):
        pass
    
    @abstractmethod
    def get_user_by_id(self, user_id):
        pass
    
    @abstractmethod
    def get_or_create_user(self, email):
        pass
    
    @abstractmethod
    def store_token(self, token, token_data):
        pass
    
    @abstractmethod
    def get_token(self, token):
        pass
    
    @abstractmethod
    def delete_token(self, token):
        pass
    
    # 2FA methods (optional - return defaults if not implemented)
    def is_2fa_enabled(self, user_id):
        return False
    
    def get_2fa_secret(self, user_id):
        return None
    
    def enable_2fa(self, user_id, secret, backup_codes):
        raise NotImplementedError("2FA not supported")
    
    def disable_2fa(self, user_id):
        raise NotImplementedError("2FA not supported")
    
    def validate_backup_code(self, user_id, code_hash):
        return False
    
    def regenerate_backup_codes(self, user_id, new_codes):
        raise NotImplementedError("2FA not supported")
    
    def store_2fa_code(self, code_data):
        raise NotImplementedError("Email 2FA not supported")
    
    def verify_2fa_code(self, user_id, code_hash):
        return False
    
    # Device binding methods (optional)
    def is_device_trusted(self, user_id, fingerprint_hash):
        return False
    
    def add_trusted_device(self, device_data):
        raise NotImplementedError("Device binding not supported")
    
    def get_trusted_devices(self, user_id):
        return []
    
    def update_device_last_seen(self, user_id, fingerprint_hash):
        pass
    
    def revoke_device(self, user_id, device_id):
        raise NotImplementedError("Device binding not supported")
    
    def store_device_challenge(self, challenge_data):
        raise NotImplementedError("Device binding not supported")
    
    def verify_device_challenge(self, token):
        return None


class InMemoryStorageAdapter(StorageAdapter):
    """In-memory storage for development. DO NOT USE IN PRODUCTION."""
    
    def __init__(self, secret_key=None, token_expiry_minutes=10, encryption_key=None):
        self.users = {}
        self.tokens = {}
        self.secret_key = secret_key or secrets.token_hex(32)
        self.token_expiry = token_expiry_minutes
        
        self.totp_secrets = {}
        self.backup_codes = {}
        self.email_2fa_codes = {}
        self.trusted_devices = {}
        self.device_challenges = {}

        self.passkey_credentials = {} 
        self.passkey_credential_counter = 0 
        
        self.encryption_key = encryption_key or Fernet.generate_key()
        self.cipher = Fernet(self.encryption_key)
        
        # Thread locks for atomic operations
        self._lock = threading.Lock()
    
    def _hash_token(self, token):
        return hmac.new(
            self.secret_key.encode(),
            token.encode(),
            hashlib.sha256
        ).hexdigest()
    
    def get_user_by_email(self, email):
        return self.users.get(email)
    
    def get_user_by_id(self, user_id):
        for user in self.users.values():
            if user.get('id') == user_id:
                return user
        return None
    
    def get_or_create_user(self, email):
        if email not in self.users:
            user_id = len(self.users) + 1
            self.users[email] = {
                'id': user_id,
                'email': email,
                'created_at': datetime.now(timezone.utc).isoformat()
            }
        return self.users[email]
    
    def store_token(self, token, token_data):
        token_hash = self._hash_token(token)
        self.tokens[token_hash] = {
            'email': token_data.get('email'),
            'next_url': token_data.get('next_url'),
            'used': False,
            'created_at': datetime.now(timezone.utc),
            'expires_at': datetime.now(timezone.utc) + timedelta(minutes=self.token_expiry)
        }
    
    def get_token(self, token):
        """Atomically retrieve and mark token as used."""
        token_hash = self._hash_token(token)
        
        with self._lock:  # Atomic operation
            token_data = self.tokens.get(token_hash)
            
            if not token_data or token_data['used']:
                return None
            
            if token_data['expires_at'] <= datetime.now(timezone.utc):
                del self.tokens[token_hash]
                return None
            
            token_data['used'] = True
            token_data['used_at'] = datetime.now(timezone.utc)
            
            return {
                'email': token_data['email'],
                'next_url': token_data.get('next_url')
            }
    
    def delete_token(self, token):
        token_hash = self._hash_token(token)
        self.tokens.pop(token_hash, None)
    
    def is_2fa_enabled(self, user_id):
        return user_id in self.totp_secrets
    
    def get_2fa_secret(self, user_id):
        encrypted = self.totp_secrets.get(user_id)
        if encrypted:
            return self.cipher.decrypt(encrypted).decode()
        return None
    
    def enable_2fa(self, user_id, secret, backup_codes):
        encrypted_secret = self.cipher.encrypt(secret.encode())
        with self._lock:
            self.totp_secrets[user_id] = encrypted_secret
            self.backup_codes[user_id] = backup_codes.copy()
    
    def disable_2fa(self, user_id):
        with self._lock:
            self.totp_secrets.pop(user_id, None)
            self.backup_codes.pop(user_id, None)
    
    def validate_backup_code(self, user_id, code_hash):
        """Atomically validate and consume a backup code."""
        with self._lock:  # Atomic operation
            if user_id not in self.backup_codes:
                return False
            
            codes = self.backup_codes[user_id]
            if code_hash in codes:
                codes.remove(code_hash)
                return True
            return False
    
    def regenerate_backup_codes(self, user_id, new_codes):
        with self._lock:
            self.backup_codes[user_id] = new_codes.copy()
    
    def store_2fa_code(self, code_data):
        user_id = code_data['user_id']
        with self._lock:
            self.email_2fa_codes[user_id] = {
                'code_hash': code_data['code_hash'],
                'expires_at': code_data['expires_at'],
                'used': False
            }
    
    def verify_2fa_code(self, user_id, code_hash):
        """Atomically verify and consume a 2FA code."""
        with self._lock:  # Atomic operation
            if user_id not in self.email_2fa_codes:
                return False
            
            data = self.email_2fa_codes[user_id]
            
            if data['used'] or data['expires_at'] <= datetime.now(timezone.utc):
                return False
            
            if secrets.compare_digest(data['code_hash'], code_hash):
                data['used'] = True
                return True
            
            return False
    
    def is_device_trusted(self, user_id, fingerprint_hash):
        if user_id not in self.trusted_devices:
            return False
        
        for device in self.trusted_devices[user_id]:
            if secrets.compare_digest(device['fingerprint_hash'], fingerprint_hash) and device['is_trusted']:
                return True
        return False
    
    def add_trusted_device(self, device_data):
        user_id = device_data['user_id']
        
        with self._lock:
            if user_id not in self.trusted_devices:
                self.trusted_devices[user_id] = []
            
            device_data['id'] = len(self.trusted_devices[user_id]) + 1
            self.trusted_devices[user_id].append(device_data)
    
    def get_trusted_devices(self, user_id):
        return self.trusted_devices.get(user_id, [])
    
    def update_device_last_seen(self, user_id, fingerprint_hash):
        if user_id not in self.trusted_devices:
            return
        
        for device in self.trusted_devices[user_id]:
            if secrets.compare_digest(device['fingerprint_hash'], fingerprint_hash):
                device['last_seen'] = datetime.now(timezone.utc)
                break
    
    def revoke_device(self, user_id, device_id):
        with self._lock:
            if user_id not in self.trusted_devices:
                return
            
            self.trusted_devices[user_id] = [
                d for d in self.trusted_devices[user_id] 
                if d.get('id') != device_id
            ]
    
    def store_device_challenge(self, challenge_data):
        token = challenge_data['token']
        with self._lock:
            self.device_challenges[token] = challenge_data
    
    def verify_device_challenge(self, token):
        """Atomically verify and consume a device challenge."""
        with self._lock:  # Atomic operation
            challenge = self.device_challenges.get(token)
            
            if not challenge or challenge.get('used'):
                return None
            
            if challenge['expires_at'] <= datetime.now(timezone.utc):
                del self.device_challenges[token]
                return None
            
            challenge['used'] = True
            return challenge

# ==================== Passkey Methods ====================
    
    def store_passkey_credential(self, credential_data):
        """Store a new passkey credential."""
        self.passkey_credential_counter += 1
        credential_id_key = credential_data['credential_id']
        
        credential = {
            'id': self.passkey_credential_counter,
            'user_id': credential_data['user_id'],
            'credential_id': credential_data['credential_id'],
            'public_key': credential_data['public_key'],
            'sign_count': credential_data['sign_count'],
            'transports': credential_data.get('transports'),
            'created_at': datetime.now(timezone.utc).isoformat(),
            'last_used_at': None,
        }
        
        self.passkey_credentials[credential_id_key] = credential
        return credential
    
    def get_passkey_credentials(self, user_id):
        """Get all passkey credentials for a user."""
        return [
            cred for cred in self.passkey_credentials.values()
            if cred['user_id'] == user_id
        ]
    
    def get_passkey_credential_by_id(self, credential_id):
        """Get a passkey credential by credential_id."""
        return self.passkey_credentials.get(credential_id)
    
    def update_passkey_sign_count(self, credential_db_id, new_sign_count):
        """Update the sign count for a credential."""
        for cred in self.passkey_credentials.values():
            if cred['id'] == credential_db_id:
                cred['sign_count'] = new_sign_count
                break
    
    def update_passkey_last_used(self, credential_db_id):
        """Update the last_used_at timestamp for a credential."""
        for cred in self.passkey_credentials.values():
            if cred['id'] == credential_db_id:
                cred['last_used_at'] = datetime.now(timezone.utc).isoformat()
                break

    def delete_passkey_credential(self, credential_db_id):
        """Delete a passkey credential by its database ID."""
        with self._lock:
            # Find and remove the credential
            for cred_id_key, cred in list(self.passkey_credentials.items()):
                if cred['id'] == credential_db_id:
                    del self.passkey_credentials[cred_id_key]
                    break

class SQLAlchemyStorageAdapter(StorageAdapter):
    """Production storage using SQLAlchemy with encryption."""
    
    def __init__(self, user_model, session, secret_key):
        from sqlalchemy import Table, Column, Integer, String, Boolean, DateTime, Text, MetaData
        
        self.session = session
        self.user_table = user_model.__table__
        
        metadata = MetaData()
        
        # Tokens table
        self.tokens_table = Table('pass0_tokens', metadata,
            Column('id', Integer, primary_key=True),
            Column('token_hash', String(64), unique=True, nullable=False),
            Column('email', String(255), nullable=False),
            Column('next_url', String(500)),
            Column('used', Boolean, default=False),
            Column('created_at', DateTime(timezone=True), nullable=False),
            Column('expires_at', DateTime(timezone=True), nullable=False),
            Column('used_at', DateTime(timezone=True))
        )
        
        # TOTP secrets table
        self.totp_secrets_table = Table('pass0_totp_secrets', metadata,
            Column('id', Integer, primary_key=True),
            Column('user_id', Integer, nullable=False, unique=True),
            Column('secret_encrypted', Text, nullable=False),
            Column('enabled_at', DateTime(timezone=True), nullable=False)
        )
        
        # Backup codes table
        self.backup_codes_table = Table('pass0_backup_codes', metadata,
            Column('id', Integer, primary_key=True),
            Column('user_id', Integer, nullable=False),
            Column('code_hash', String(64), nullable=False),
            Column('used', Boolean, default=False),
            Column('created_at', DateTime(timezone=True), nullable=False)
        )
        
        # Email 2FA codes table
        self.email_2fa_codes_table = Table('pass0_email_2fa_codes', metadata,
            Column('id', Integer, primary_key=True),
            Column('user_id', Integer, nullable=False),
            Column('code_hash', String(64), nullable=False),
            Column('created_at', DateTime(timezone=True), nullable=False),
            Column('expires_at', DateTime(timezone=True), nullable=False),
            Column('used', Boolean, default=False)
        )
        
        # Trusted devices table
        self.trusted_devices_table = Table('pass0_trusted_devices', metadata,
            Column('id', Integer, primary_key=True),
            Column('user_id', Integer, nullable=False),
            Column('fingerprint_hash', String(64), nullable=False),
            Column('device_name', String(255)),
            Column('ip_address', String(45)),
            Column('user_agent', Text),
            Column('first_seen', DateTime(timezone=True), nullable=False),
            Column('last_seen', DateTime(timezone=True), nullable=False),
            Column('is_trusted', Boolean, default=True)
        )
        
        # Device challenges table
        self.device_challenges_table = Table('pass0_device_challenges', metadata,
            Column('id', Integer, primary_key=True),
            Column('token', String(64), unique=True, nullable=False),
            Column('user_id', Integer, nullable=False),
            Column('fingerprint_hash', String(64), nullable=False),
            Column('created_at', DateTime(timezone=True), nullable=False),
            Column('expires_at', DateTime(timezone=True), nullable=False),
            Column('used', Boolean, default=False)
        )

        # Passkey credentials table
        self.passkey_credentials_table = Table('pass0_passkey_credentials', metadata,
            Column('id', Integer, primary_key=True),
            Column('user_id', Integer, nullable=False),
            Column('credential_id', String(1024), unique=True, nullable=False),
            Column('public_key', Text, nullable=False),
            Column('sign_count', Integer, default=0, nullable=False),
            Column('transports', String(255)),
            Column('created_at', DateTime(timezone=True), nullable=False),
            Column('last_used_at', DateTime(timezone=True))
        )
        
        # Generate proper Fernet key (always use generated key for security)
        self.encryption_key = Fernet.generate_key()
        self.cipher = Fernet(self.encryption_key)
        
        metadata.create_all(session.get_bind())
    
    def init_app(self, app):
        """Initialize with Flask app if needed."""
        pass
    
    def _hash_token(self, token):
        return hashlib.sha256(token.encode()).hexdigest()
    
    def get_user_by_email(self, email):
        result = self.session.execute(
            self.user_table.select().where(
                self.user_table.c.email == email
            )
        ).fetchone()
        return dict(result._mapping) if result else None
    
    def get_user_by_id(self, user_id):
        result = self.session.execute(
            self.user_table.select().where(
                self.user_table.c.id == user_id
            )
        ).fetchone()
        return dict(result._mapping) if result else None
    
    def get_or_create_user(self, email):
        user = self.get_user_by_email(email)
        
        if not user:
            result = self.session.execute(
                self.user_table.insert().values(
                    email=email,
                    created_at=datetime.now(timezone.utc)
                ).returning(self.user_table)
            )
            self.session.flush()
            user = dict(result.fetchone()._mapping)
        
        return user
    
    def store_token(self, token, token_data):
        token_hash = self._hash_token(token)
        expiry_minutes = 10
        
        self.session.execute(
            self.tokens_table.insert().values(
                token_hash=token_hash,
                email=token_data.get('email'),
                next_url=token_data.get('next_url'),
                used=False,
                created_at=datetime.now(timezone.utc),
                expires_at=datetime.now(timezone.utc) + timedelta(minutes=expiry_minutes)
            )
        )
        self.session.commit()
    
    def get_token(self, token):
        """Atomically retrieve and mark token as used via UPDATE...RETURNING."""
        token_hash = self._hash_token(token)
        
        # Single atomic UPDATE that checks conditions and marks as used
        result = self.session.execute(
            self.tokens_table.update().where(
                self.tokens_table.c.token_hash == token_hash,
                self.tokens_table.c.used == False,
                self.tokens_table.c.expires_at >= datetime.now(timezone.utc)
            ).values(
                used=True, 
                used_at=datetime.now(timezone.utc)
            ).returning(
                self.tokens_table.c.email,
                self.tokens_table.c.next_url
            )
        ).fetchone()
        
        self.session.commit()
        
        if not result:
            return None
        
        return {'email': result.email, 'next_url': result.next_url}
    
    def delete_token(self, token):
        token_hash = self._hash_token(token)
        self.session.execute(
            self.tokens_table.delete().where(
                self.tokens_table.c.token_hash == token_hash
            )
        )
        self.session.commit()
    
    def is_2fa_enabled(self, user_id):
        result = self.session.execute(
            self.totp_secrets_table.select().where(
                self.totp_secrets_table.c.user_id == user_id
            )
        ).fetchone()
        return result is not None
    
    def get_2fa_secret(self, user_id):
        result = self.session.execute(
            self.totp_secrets_table.select().where(
                self.totp_secrets_table.c.user_id == user_id
            )
        ).fetchone()
        
        if result:
            return self.cipher.decrypt(result.secret_encrypted.encode()).decode()
        return None
    
    def enable_2fa(self, user_id, secret, backup_codes):
        encrypted = self.cipher.encrypt(secret.encode()).decode()
        self.session.execute(
            self.totp_secrets_table.insert().values(
                user_id=user_id,
                secret_encrypted=encrypted,
                enabled_at=datetime.now(timezone.utc)
            )
        )
        
        for code_hash in backup_codes:
            self.session.execute(
                self.backup_codes_table.insert().values(
                    user_id=user_id,
                    code_hash=code_hash,
                    used=False,
                    created_at=datetime.now(timezone.utc)
                )
            )
        
        self.session.commit()
    
    def disable_2fa(self, user_id):
        self.session.execute(
            self.totp_secrets_table.delete().where(
                self.totp_secrets_table.c.user_id == user_id
            )
        )
        self.session.execute(
            self.backup_codes_table.delete().where(
                self.backup_codes_table.c.user_id == user_id
            )
        )
        self.session.commit()
    
    def validate_backup_code(self, user_id, code_hash):
        """Atomically validate and consume a backup code via UPDATE...RETURNING."""
        # Single atomic UPDATE that checks conditions and marks as used
        result = self.session.execute(
            self.backup_codes_table.update().where(
                self.backup_codes_table.c.user_id == user_id,
                self.backup_codes_table.c.code_hash == code_hash,
                self.backup_codes_table.c.used == False
            ).values(
                used=True
            ).returning(
                self.backup_codes_table.c.id
            )
        ).fetchone()
        
        self.session.commit()
        return result is not None
    
    def regenerate_backup_codes(self, user_id, new_codes):
        self.session.execute(
            self.backup_codes_table.delete().where(
                self.backup_codes_table.c.user_id == user_id
            )
        )
        
        for code_hash in new_codes:
            self.session.execute(
                self.backup_codes_table.insert().values(
                    user_id=user_id,
                    code_hash=code_hash,
                    used=False,
                    created_at=datetime.now(timezone.utc)
                )
            )
        
        self.session.commit()
    
    def store_2fa_code(self, code_data):
        self.session.execute(
            self.email_2fa_codes_table.insert().values(
                user_id=code_data['user_id'],
                code_hash=code_data['code_hash'],
                created_at=code_data['created_at'],
                expires_at=code_data['expires_at'],
                used=False
            )
        )
        self.session.commit()
    
    def verify_2fa_code(self, user_id, code_hash):
        """Atomically verify and consume a 2FA code via UPDATE...RETURNING."""
        # Single atomic UPDATE that checks conditions and marks as used
        result = self.session.execute(
            self.email_2fa_codes_table.update().where(
                self.email_2fa_codes_table.c.user_id == user_id,
                self.email_2fa_codes_table.c.code_hash == code_hash,
                self.email_2fa_codes_table.c.used == False,
                self.email_2fa_codes_table.c.expires_at >= datetime.now(timezone.utc)
            ).values(
                used=True
            ).returning(
                self.email_2fa_codes_table.c.id
            )
        ).fetchone()
        
        self.session.commit()
        return result is not None
    
    def is_device_trusted(self, user_id, fingerprint_hash):
        result = self.session.execute(
            self.trusted_devices_table.select().where(
                self.trusted_devices_table.c.user_id == user_id,
                self.trusted_devices_table.c.fingerprint_hash == fingerprint_hash,
                self.trusted_devices_table.c.is_trusted == True
            )
        ).fetchone()
        return result is not None
    
    def add_trusted_device(self, device_data):
        self.session.execute(
            self.trusted_devices_table.insert().values(
                user_id=device_data['user_id'],
                fingerprint_hash=device_data['fingerprint_hash'],
                device_name=device_data['device_name'],
                ip_address=device_data.get('ip_address'),
                user_agent=device_data.get('user_agent'),
                first_seen=device_data['first_seen'],
                last_seen=device_data['last_seen'],
                is_trusted=device_data.get('is_trusted', True)
            )
        )
        self.session.commit()
    
    def get_trusted_devices(self, user_id):
        results = self.session.execute(
            self.trusted_devices_table.select().where(
                self.trusted_devices_table.c.user_id == user_id,
                self.trusted_devices_table.c.is_trusted == True
            ).order_by(self.trusted_devices_table.c.last_seen.desc())
        ).fetchall()
        
        return [dict(row._mapping) for row in results]
    
    def update_device_last_seen(self, user_id, fingerprint_hash):
        self.session.execute(
            self.trusted_devices_table.update().where(
                self.trusted_devices_table.c.user_id == user_id,
                self.trusted_devices_table.c.fingerprint_hash == fingerprint_hash
            ).values(last_seen=datetime.now(timezone.utc))
        )
        self.session.commit()
    
    def revoke_device(self, user_id, device_id):
        self.session.execute(
            self.trusted_devices_table.delete().where(
                self.trusted_devices_table.c.id == device_id,
                self.trusted_devices_table.c.user_id == user_id
            )
        )
        self.session.commit()
    
    def store_device_challenge(self, challenge_data):
        self.session.execute(
            self.device_challenges_table.insert().values(
                token=challenge_data['token'],
                user_id=challenge_data['user_id'],
                fingerprint_hash=challenge_data['fingerprint_hash'],
                created_at=challenge_data['created_at'],
                expires_at=challenge_data['expires_at'],
                used=False
            )
        )
        self.session.commit()
    
    def verify_device_challenge(self, token):
        """Atomically verify and consume a device challenge via UPDATE...RETURNING."""
        # Single atomic UPDATE that checks conditions and marks as used
        result = self.session.execute(
            self.device_challenges_table.update().where(
                self.device_challenges_table.c.token == token,
                self.device_challenges_table.c.used == False,
                self.device_challenges_table.c.expires_at >= datetime.now(timezone.utc)
            ).values(
                used=True
            ).returning(
                self.device_challenges_table.c.user_id,
                self.device_challenges_table.c.fingerprint_hash,
                self.device_challenges_table.c.created_at,
                self.device_challenges_table.c.expires_at
            )
        ).fetchone()
        
        self.session.commit()
        
        if not result:
            return None
        
        return dict(result._mapping)

# ==================== Passkey Methods (SQLAlchemyStorageAdapter) ====================
    
    def store_passkey_credential(self, credential_data):
        """Store a new passkey credential."""
        self.session.execute(
            self.passkey_credentials_table.insert().values(
                user_id=credential_data['user_id'],
                credential_id=credential_data['credential_id'],
                public_key=credential_data['public_key'],
                sign_count=credential_data['sign_count'],
                transports=credential_data.get('transports'),
                created_at=datetime.now(timezone.utc)
            )
        )
        self.session.commit()
        return credential_data
        
    def get_passkey_credentials(self, user_id):
        """Get all passkey credentials for a user."""
        from sqlalchemy import Table, Column, Integer, String, DateTime, Text, MetaData
        
        try:
            metadata = MetaData()
            passkey_table = Table('pass0_passkey_credentials', metadata,
                autoload_with=self.session.get_bind()
            )
            
            results = self.session.execute(
                passkey_table.select().where(passkey_table.c.user_id == user_id)
            ).fetchall()
            
            return [dict(row._mapping) for row in results]
        except Exception:
            return []
    
    def get_passkey_credential_by_id(self, credential_id):
        """Get a passkey credential by credential_id."""
        from sqlalchemy import Table, MetaData
        
        try:
            metadata = MetaData()
            passkey_table = Table('pass0_passkey_credentials', metadata,
                autoload_with=self.session.get_bind()
            )
            
            result = self.session.execute(
                passkey_table.select().where(passkey_table.c.credential_id == credential_id)
            ).fetchone()
            
            return dict(result._mapping) if result else None
        except Exception:
            return None
    
    def update_passkey_sign_count(self, credential_db_id, new_sign_count):
        """Update the sign count for a credential."""
        from sqlalchemy import Table, MetaData
        
        try:
            metadata = MetaData()
            passkey_table = Table('pass0_passkey_credentials', metadata,
                autoload_with=self.session.get_bind()
            )
            
            self.session.execute(
                passkey_table.update().where(
                    passkey_table.c.id == credential_db_id
                ).values(sign_count=new_sign_count)
            )
            self.session.commit()
        except Exception:
            pass

    def update_passkey_last_used(self, credential_db_id):
        """Update the last_used_at timestamp for a credential."""
        from sqlalchemy import Table, MetaData
        
        try:
            metadata = MetaData()
            passkey_table = Table('pass0_passkey_credentials', metadata,
                autoload_with=self.session.get_bind()
            )
            
            self.session.execute(
                passkey_table.update().where(
                    passkey_table.c.id == credential_db_id
                ).values(last_used_at=datetime.now(timezone.utc))
            )
            self.session.commit()
        except Exception:
            pass
    
    def delete_passkey_credential(self, credential_db_id):
        """Delete a passkey credential by its database ID."""
        try:
            self.session.execute(
                self.passkey_credentials_table.delete().where(
                    self.passkey_credentials_table.c.id == credential_db_id
                )
            )
            self.session.commit()
        except Exception:
            pass

# Legacy storage
_users = {}
_tokens = {}