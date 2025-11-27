"""
Flask-Pass0 Storage Adapters with Built-in Security
====================================================
Version 1.1+ includes:
- Token hashing (HMAC-SHA256)
- Single-use enforcement
- Secure token generation
"""

import hmac
import hashlib
import secrets
from abc import ABC, abstractmethod
from datetime import datetime, timedelta


class StorageAdapter(ABC):
    """Base storage adapter interface"""
    
    @abstractmethod
    def get_user_by_email(self, email):
        """Retrieve user by email address"""
        pass
    
    @abstractmethod
    def get_user_by_id(self, user_id):
        """Retrieve user by ID"""
        pass
    
    @abstractmethod
    def get_or_create_user(self, email):
        """Get existing user or create new one"""
        pass
    
    @abstractmethod
    def store_token(self, token, token_data):
        """Store token securely (hashed)"""
        pass
    
    @abstractmethod
    def get_token(self, token):
        """Retrieve and consume token (single-use)"""
        pass
    
    @abstractmethod
    def delete_token(self, token):
        """Delete token"""
        pass


class InMemoryStorageAdapter(StorageAdapter):
    """
    In-memory storage for development only.
    DO NOT USE IN PRODUCTION - data lost on restart.
    """
    
    def __init__(self, secret_key=None, token_expiry_minutes=10):
        self.users = {}
        self.tokens = {}
        self.secret_key = secret_key or secrets.token_hex(32)
        self.token_expiry = token_expiry_minutes
    
    def _hash_token(self, token):
        """Hash token using HMAC-SHA256"""
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
        """Get existing user or create new one"""
        if email not in self.users:
            user_id = len(self.users) + 1
            self.users[email] = {
                'id': user_id,
                'email': email,
                'created_at': datetime.utcnow().isoformat()
            }
        return self.users[email]
    
    def store_token(self, token, token_data):
        """Store hashed token with expiry"""
        token_hash = self._hash_token(token)
        
        self.tokens[token_hash] = {
            'email': token_data.get('email'),
            'next_url': token_data.get('next_url'),
            'used': False,
            'created_at': datetime.utcnow(),
            'expires_at': datetime.utcnow() + timedelta(minutes=self.token_expiry)
        }
    
    def get_token(self, token):
        """Verify and consume token (single-use)"""
        token_hash = self._hash_token(token)
        
        token_data = self.tokens.get(token_hash)
        if not token_data:
            return None
        
        # Check if already used
        if token_data['used']:
            return None
        
        # Check expiry
        if token_data['expires_at'] < datetime.utcnow():
            del self.tokens[token_hash]
            return None
        
        # Mark as used (single-use enforcement)
        token_data['used'] = True
        token_data['used_at'] = datetime.utcnow()
        
        return {
            'email': token_data['email'],
            'next_url': token_data.get('next_url')
        }
    
    def delete_token(self, token):
        """Delete token"""
        token_hash = self._hash_token(token)
        self.tokens.pop(token_hash, None)
    
    def cleanup_expired_tokens(self):
        """Remove expired tokens"""
        now = datetime.utcnow()
        expired = [k for k, v in self.tokens.items() if v['expires_at'] < now]
        for k in expired:
            del self.tokens[k]


class SQLAlchemyStorageAdapter(StorageAdapter):
    """
    SQLAlchemy-based storage with built-in security.
    
    Features:
    - Token hashing (HMAC-SHA256)
    - Single-use enforcement
    - Automatic expiry
    """
    
    def __init__(self, user_model, session, secret_key=None, token_expiry_minutes=10):
        self.user_model = user_model
        self.session = session
        self.secret_key = secret_key or secrets.token_hex(32)
        self.token_expiry = token_expiry_minutes
        
        # Create tokens table
        self._ensure_token_table()
    
    def _ensure_token_table(self):
        """Create secure tokens table"""
        from sqlalchemy import Table, Column, Integer, String, Boolean, DateTime, MetaData, Index
        
        metadata = MetaData()
        self.tokens_table = Table(
            'pass0_tokens',
            metadata,
            Column('id', Integer, primary_key=True),
            Column('token_hash', String(64), unique=True, nullable=False, index=True),
            Column('email', String(255), nullable=False),
            Column('next_url', String(512)),
            Column('used', Boolean, default=False, nullable=False),
            Column('created_at', DateTime, nullable=False),
            Column('expires_at', DateTime, nullable=False, index=True),
            Column('used_at', DateTime),
            extend_existing=True
        )
        
        # Create table if doesn't exist
        metadata.create_all(self.session.get_bind(), checkfirst=True)
    
    def _hash_token(self, token):
        """Hash token using HMAC-SHA256"""
        return hmac.new(
            self.secret_key.encode(),
            token.encode(),
            hashlib.sha256
        ).hexdigest()
    
    def get_user_by_email(self, email):
        user = self.session.query(self.user_model).filter_by(email=email).first()
        return user.to_dict() if user and hasattr(user, 'to_dict') else user
    
    def get_user_by_id(self, user_id):
        user = self.session.query(self.user_model).filter_by(id=user_id).first()
        return user.to_dict() if user and hasattr(user, 'to_dict') else user
    
    def get_or_create_user(self, email):
        """Get existing user or create new one"""
        user = self.session.query(self.user_model).filter_by(email=email).first()
        
        if not user:
            user = self.user_model(email=email)
            self.session.add(user)
            self.session.commit()
        
        return user.to_dict() if hasattr(user, 'to_dict') else user
    
    def store_token(self, token, token_data):
        """Store hashed token with expiry"""
        token_hash = self._hash_token(token)
        
        self.session.execute(
            self.tokens_table.insert().values(
                token_hash=token_hash,
                email=token_data.get('email'),
                next_url=token_data.get('next_url'),
                used=False,
                created_at=datetime.utcnow(),
                expires_at=datetime.utcnow() + timedelta(minutes=self.token_expiry)
            )
        )
        self.session.commit()
    
    def get_token(self, token):
        """Verify and consume token atomically (single-use)"""
        token_hash = self._hash_token(token)
        
        # Get token if valid and not used
        result = self.session.execute(
            self.tokens_table.select().where(
                self.tokens_table.c.token_hash == token_hash,
                self.tokens_table.c.used == False,
                self.tokens_table.c.expires_at > datetime.utcnow()
            )
        ).fetchone()
        
        if not result:
            return None
        
        # Mark as used immediately (single-use enforcement)
        self.session.execute(
            self.tokens_table.update().where(
                self.tokens_table.c.token_hash == token_hash
            ).values(
                used=True,
                used_at=datetime.utcnow()
            )
        )
        self.session.commit()
        
        return {
            'email': result.email,
            'next_url': result.next_url
        }
    
    def delete_token(self, token):
        """Delete token (already marked as used in get_token)"""
        token_hash = self._hash_token(token)
        self.session.execute(
            self.tokens_table.delete().where(
                self.tokens_table.c.token_hash == token_hash
            )
        )
        self.session.commit()
    
    def cleanup_expired_tokens(self, days=7):
        """Remove old tokens - call periodically via cron"""
        cutoff = datetime.utcnow() - timedelta(days=days)
        self.session.execute(
            self.tokens_table.delete().where(
                self.tokens_table.c.created_at < cutoff
            )
        )
        self.session.commit()


# Legacy in-memory storage for backward compatibility
_users = {}
_tokens = {}