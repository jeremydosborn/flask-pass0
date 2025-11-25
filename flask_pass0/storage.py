"""
Storage adapters for Flask-Pass0.
This module provides abstract and concrete storage implementations.
"""
from abc import ABC, abstractmethod
from datetime import datetime
from typing import Dict, Any, Optional, List, Union
import json

# In-memory storage for development/testing
_users = {}  # {email: user_dict}
_tokens = {}  # {token: token_data_dict}

class StorageAdapter(ABC):
    """Abstract base class for storage adapters.
    
    Implement this class to provide custom storage for users and tokens.
    """
    
    def init_app(self, app):
        """Initialize the storage adapter with the Flask app."""
        pass
    
    @abstractmethod
    def get_user_by_email(self, email: str) -> Optional[Dict[str, Any]]:
        """Get a user by email address."""
        pass
    
    @abstractmethod
    def get_user_by_id(self, user_id: Union[str, int]) -> Optional[Dict[str, Any]]:
        """Get a user by ID."""
        pass
    
    @abstractmethod
    def create_user(self, email: str, **kwargs) -> Dict[str, Any]:
        """Create a new user."""
        pass
    
    def get_or_create_user(self, email: str) -> Dict[str, Any]:
        """Get a user by email or create if not exists."""
        user = self.get_user_by_email(email)
        if not user:
            user = self.create_user(email)
        return user
    
    @abstractmethod
    def update_user(self, user_id: Union[str, int], **kwargs) -> Dict[str, Any]:
        """Update a user."""
        pass
    
    @abstractmethod
    def delete_user(self, user_id: Union[str, int]) -> bool:
        """Delete a user."""
        pass
    
    @abstractmethod
    def store_token(self, token: str, token_data: Dict[str, Any]) -> None:
        """Store a token with its associated data."""
        pass
    
    @abstractmethod
    def get_token(self, token: str) -> Optional[Dict[str, Any]]:
        """Get token data by token."""
        pass
    
    @abstractmethod
    def delete_token(self, token: str) -> bool:
        """Delete a token."""
        pass


class MemoryStorageAdapter(StorageAdapter):
    """In-memory storage adapter for development and testing."""
    
    def get_user_by_email(self, email: str) -> Optional[Dict[str, Any]]:
        """Get a user by email address."""
        return _users.get(email)
    
    def get_user_by_id(self, user_id: Union[str, int]) -> Optional[Dict[str, Any]]:
        """Get a user by ID."""
        for user in _users.values():
            if str(user.get('id')) == str(user_id):
                return user
        return None
    
    def create_user(self, email: str, **kwargs) -> Dict[str, Any]:
        """Create a new user."""
        user_id = len(_users) + 1
        user = {
            'id': user_id,
            'email': email,
            'name': kwargs.get('name', email.split('@')[0]),
            'created_at': datetime.now().isoformat(),
            **kwargs
        }
        _users[email] = user
        return user
    
    def update_user(self, user_id: Union[str, int], **kwargs) -> Dict[str, Any]:
        """Update a user."""
        user = self.get_user_by_id(user_id)
        if not user:
            raise ValueError(f"User with ID {user_id} not found")
        
        # Update user fields
        for key, value in kwargs.items():
            user[key] = value
        
        # Update in _users dict (by email)
        _users[user['email']] = user
        return user
    
    def delete_user(self, user_id: Union[str, int]) -> bool:
        """Delete a user."""
        user = self.get_user_by_id(user_id)
        if not user:
            return False
        
        del _users[user['email']]
        return True
    
    def store_token(self, token: str, token_data: Dict[str, Any]) -> None:
        """Store a token with its associated data."""
        _tokens[token] = token_data
    
    def get_token(self, token: str) -> Optional[Dict[str, Any]]:
        """Get token data by token."""
        return _tokens.get(token)
    
    def delete_token(self, token: str) -> bool:
        """Delete a token."""
        if token in _tokens:
            del _tokens[token]
            return True
        return False


class SQLAlchemyStorageAdapter(StorageAdapter):
    """SQLAlchemy storage adapter for SQL databases."""
    
    def __init__(self, user_model=None, token_model=None, session=None):
        """Initialize the SQLAlchemy storage adapter.
        
        Args:
            user_model: SQLAlchemy model for users
            token_model: SQLAlchemy model for tokens
            session: SQLAlchemy session
        """
        self.db = None
        self.User = user_model
        self.Token = token_model
        self.session = session
    
    def init_app(self, app):
        """Initialize the storage adapter with the Flask app."""
        from flask_sqlalchemy import SQLAlchemy
        
        # If models not provided, use default
        if not hasattr(self, 'db') or not self.db:
            self.db = SQLAlchemy(app)
            
            # Define models if not provided
            if not self.User:
                class User(self.db.Model):
                    __tablename__ = 'pass0_users'
                    id = self.db.Column(self.db.Integer, primary_key=True)
                    email = self.db.Column(self.db.String(255), unique=True, nullable=False)
                    name = self.db.Column(self.db.String(255), nullable=True)
                    created_at = self.db.Column(self.db.DateTime, default=datetime.utcnow)
                    
                    def to_dict(self):
                        return {
                            'id': self.id,
                            'email': self.email,
                            'name': self.name,
                            'created_at': self.created_at.isoformat() if self.created_at else None
                        }
                
                self.User = User
            
            if not self.Token:
                class Token(self.db.Model):
                    __tablename__ = 'pass0_tokens'
                    token = self.db.Column(self.db.String(255), primary_key=True)
                    email = self.db.Column(self.db.String(255), nullable=False)
                    expiry = self.db.Column(self.db.DateTime, nullable=False)
                    next_url = self.db.Column(self.db.Text, nullable=True)
                    data = self.db.Column(self.db.Text, nullable=True)  # For additional data
                    
                    def to_dict(self):
                        result = {
                            'email': self.email,
                            'expiry': self.expiry,
                            'next_url': self.next_url
                        }
                        
                        # Parse additional data if present
                        if self.data:
                            try:
                                additional_data = json.loads(self.data)
                                result.update(additional_data)
                            except:
                                pass
                                
                        return result
                
                self.Token = Token
            
            # Create tables
            with app.app_context():
                self.db.create_all()
            
            # Use db.session if session not provided
            if not self.session:
                self.session = self.db.session
    
    def get_user_by_email(self, email: str) -> Optional[Dict[str, Any]]:
        """Get a user by email address."""
        user = self.User.query.filter_by(email=email).first()
        if user:
            return user.to_dict()
        return None
    
    def get_user_by_id(self, user_id: Union[str, int]) -> Optional[Dict[str, Any]]:
        """Get a user by ID."""
        user = self.User.query.get(user_id)
        if user:
            return user.to_dict()
        return None
    
    def create_user(self, email: str, **kwargs) -> Dict[str, Any]:
        """Create a new user."""
        user = self.User(
            email=email,
            name=kwargs.get('name', email.split('@')[0]),
            **{k: v for k, v in kwargs.items() if hasattr(self.User, k)}
        )
        self.session.add(user)
        self.session.commit()
        return user.to_dict()
    
    def update_user(self, user_id: Union[str, int], **kwargs) -> Dict[str, Any]:
        """Update a user."""
        user = self.User.query.get(user_id)
        if not user:
            raise ValueError(f"User with ID {user_id} not found")
        
        # Update user fields
        for key, value in kwargs.items():
            if hasattr(user, key):
                setattr(user, key, value)
        
        self.session.commit()
        return user.to_dict()
    
    def delete_user(self, user_id: Union[str, int]) -> bool:
        """Delete a user."""
        user = self.User.query.get(user_id)
        if not user:
            return False
        
        self.session.delete(user)
        self.session.commit()
        return True
    
    def store_token(self, token: str, token_data: Dict[str, Any]) -> None:
        """Store a token with its associated data."""
        # Extract standard fields
        email = token_data.get('email')
        expiry = token_data.get('expiry')
        next_url = token_data.get('next_url')
        
        # Store additional data as JSON
        additional_data = {k: v for k, v in token_data.items() 
                          if k not in ['email', 'expiry', 'next_url']}
        
        # Create token
        token_obj = self.Token(
            token=token,
            email=email,
            expiry=expiry,
            next_url=next_url,
            data=json.dumps(additional_data) if additional_data else None
        )
        
        self.session.add(token_obj)
        self.session.commit()
    
    def get_token(self, token: str) -> Optional[Dict[str, Any]]:
        """Get token data by token."""
        token_obj = self.Token.query.get(token)
        if token_obj:
            return token_obj.to_dict()
        return None
    
    def delete_token(self, token: str) -> bool:
        """Delete a token."""
        token_obj = self.Token.query.get(token)
        if not token_obj:
            return False
        
        self.session.delete(token_obj)
        self.session.commit()
        return True


# Factory function to get the default storage adapter
def get_storage_adapter():
    """Get the default storage adapter."""
    return MemoryStorageAdapter()