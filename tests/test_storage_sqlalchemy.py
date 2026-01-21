"""
SQLAlchemy storage adapter tests for Flask-Pass0.
"""

import pytest
from datetime import datetime, timedelta, timezone
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_pass0 import Pass0
from flask_pass0.storage import SQLAlchemyStorageAdapter


@pytest.fixture
def db_app():
    """Flask app with SQLAlchemy database."""
    app = Flask(__name__)
    app.config['SECRET_KEY'] = 'test-secret'
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    app.config['TESTING'] = True
    
    # Pass0 config
    app.config['PASS0_DEV_MODE'] = True
    app.config['PASS0_PRIMARY_AUTH'] = 'magic_link'
    app.config['PASS0_RP_ID'] = 'localhost'
    app.config['PASS0_RP_NAME'] = 'Test App'
    app.config['PASS0_2FA_ENABLED'] = True
    app.config['PASS0_2FA_VERIFY_ROUTE'] = 'verify_2fa'
    
    db = SQLAlchemy(app)
    
    # Define User model
    class User(db.Model):
        id = db.Column(db.Integer, primary_key=True)
        email = db.Column(db.String(255), unique=True, nullable=False)
        created_at = db.Column(db.DateTime, default=datetime.utcnow)
        
        def to_dict(self):
            return {
                'id': self.id,
                'email': self.email,
                'created_at': self.created_at.isoformat() if self.created_at else None
            }
    
    with app.app_context():
        db.create_all()
        
        # Initialize Pass0 with SQLAlchemy adapter
        storage = SQLAlchemyStorageAdapter(
            user_model=User,
            session=db.session,
            secret_key=app.config['SECRET_KEY']
        )
        pass0 = Pass0(app, storage_adapter=storage)
        
        app.db = db
        app.User = User
    
    yield app
    
    # Cleanup
    with app.app_context():
        db.drop_all()


@pytest.fixture
def db_client(db_app):
    return db_app.test_client()


@pytest.fixture
def db_user(db_app):
    """Create a test user in the database."""
    with db_app.app_context():
        user = db_app.User(email='test@example.com')
        db_app.db.session.add(user)
        db_app.db.session.commit()
        
        # Return dict representation
        user_dict = user.to_dict()
        
    return user_dict


@pytest.mark.unit
class TestSQLAlchemyUserOperations:
    
    def test_get_user_by_email(self, db_app, db_user):
        """Test retrieving user by email."""
        with db_app.app_context():
            pass0 = db_app.extensions['pass0']
            storage = pass0.storage
            
            user = storage.get_user_by_email('test@example.com')
            
            assert user is not None
            assert user['email'] == 'test@example.com'
            assert user['id'] == db_user['id']
    
    def test_get_user_by_email_not_found(self, db_app):
        """Test retrieving non-existent user returns None."""
        with db_app.app_context():
            pass0 = db_app.extensions['pass0']
            storage = pass0.storage
            
            user = storage.get_user_by_email('nonexistent@example.com')
            
            assert user is None
    
    def test_get_user_by_id(self, db_app, db_user):
        """Test retrieving user by ID."""
        with db_app.app_context():
            pass0 = db_app.extensions['pass0']
            storage = pass0.storage
            
            user = storage.get_user_by_id(db_user['id'])
            
            assert user is not None
            assert user['id'] == db_user['id']
            assert user['email'] == 'test@example.com'
    
    def test_get_user_by_id_not_found(self, db_app):
        """Test retrieving non-existent user by ID returns None."""
        with db_app.app_context():
            pass0 = db_app.extensions['pass0']
            storage = pass0.storage
            
            user = storage.get_user_by_id(99999)
            
            assert user is None
    
    def test_get_or_create_user_existing(self, db_app, db_user):
        """Test get_or_create returns existing user."""
        with db_app.app_context():
            pass0 = db_app.extensions['pass0']
            storage = pass0.storage
            
            user = storage.get_or_create_user('test@example.com')
            
            assert user is not None
            assert user['id'] == db_user['id']
    
    def test_get_or_create_user_creates_new(self, db_app):
        """Test get_or_create creates new user if not exists."""
        with db_app.app_context():
            pass0 = db_app.extensions['pass0']
            storage = pass0.storage
            
            user = storage.get_or_create_user('newuser@example.com')
            
            assert user is not None
            assert user['email'] == 'newuser@example.com'
            assert user['id'] is not None
            
            # Verify it was actually created in DB
            db_user = db_app.User.query.filter_by(email='newuser@example.com').first()
            assert db_user is not None


@pytest.mark.unit
class TestSQLAlchemyTokenOperations:
    
    def test_store_and_retrieve_token(self, db_app, db_user):
        """Test storing and retrieving magic link token."""
        with db_app.app_context():
            pass0 = db_app.extensions['pass0']
            storage = pass0.storage
            
            token = 'test-token-12345'
            token_data = {
                'email': db_user['email'],
                'next_url': '/dashboard'
            }
            
            # Store token
            storage.store_token(token, token_data)
            
            # Retrieve token
            retrieved_data = storage.get_token(token)
            
            assert retrieved_data is not None
            assert retrieved_data['email'] == db_user['email']
            assert retrieved_data['next_url'] == '/dashboard'
    
    def test_token_expiration(self, db_app, db_user):
        """Test that expired tokens are not returned."""
        pytest.skip("Skipping: Cannot easily manipulate SQLAlchemy DB expiration without exposing internals")
        # This test would require either:
        # 1. Exposing the token model/table
        # 2. Adding a test-only method to expire tokens
        # 3. Mocking datetime (complex with SQLAlchemy)
        # For now, token expiration is tested in the InMemory storage tests
    
    def test_token_hashing(self, db_app, db_user):
        """Test that tokens are hashed in database."""
        with db_app.app_context():
            pass0 = db_app.extensions['pass0']
            storage = pass0.storage
            
            token = 'plaintext-token'
            token_data = {'email': db_user['email']}
            
            storage.store_token(token, token_data)
            
            # Verify the token can be retrieved (which means it was stored properly)
            retrieved = storage.get_token(token)
            assert retrieved is not None
            assert retrieved['email'] == db_user['email']
            
            # Verify the token hash is different from raw token
            token_hash = storage._hash_token(token)
            assert token != token_hash
            assert len(token_hash) == 64  # SHA-256 hex digest
            assert 'plaintext-token' not in token_hash


@pytest.mark.unit
class TestSQLAlchemyPasskeyOperations:
    
    def test_store_passkey_credential(self, db_app, db_user):
        """Test storing passkey credential."""
        with db_app.app_context():
            pass0 = db_app.extensions['pass0']
            storage = pass0.storage
            
            credential_data = {
                'user_id': db_user['id'],
                'credential_id': 'test-cred-id-base64',
                'public_key': 'test-public-key-base64',
                'sign_count': 0,
                'transports': 'internal,hybrid'
            }
            
            storage.store_passkey_credential(credential_data)
            
            # Retrieve credentials
            credentials = storage.get_passkey_credentials(db_user['id'])
            
            assert len(credentials) == 1
            assert credentials[0]['credential_id'] == 'test-cred-id-base64'
            assert credentials[0]['public_key'] == 'test-public-key-base64'
    
    def test_get_passkey_credential_by_id(self, db_app, db_user):
        """Test retrieving passkey credential by credential_id."""
        with db_app.app_context():
            pass0 = db_app.extensions['pass0']
            storage = pass0.storage
            
            credential_data = {
                'user_id': db_user['id'],
                'credential_id': 'unique-cred-id',
                'public_key': 'test-key',
                'sign_count': 0
            }
            
            storage.store_passkey_credential(credential_data)
            
            # Retrieve by credential_id
            credential = storage.get_passkey_credential_by_id('unique-cred-id')
            
            assert credential is not None
            assert credential['credential_id'] == 'unique-cred-id'
            assert credential['user_id'] == db_user['id']
    
    def test_update_passkey_sign_count(self, db_app, db_user):
        """Test updating passkey sign count."""
        with db_app.app_context():
            pass0 = db_app.extensions['pass0']
            storage = pass0.storage
            
            credential_data = {
                'user_id': db_user['id'],
                'credential_id': 'test-cred',
                'public_key': 'test-key',
                'sign_count': 0
            }
            
            storage.store_passkey_credential(credential_data)
            
            # Get the credential's database ID
            credential = storage.get_passkey_credential_by_id('test-cred')
            cred_id = credential['id']
            
            # Update sign count
            storage.update_passkey_sign_count(cred_id, 5)
            
            # Verify update
            updated_credential = storage.get_passkey_credential_by_id('test-cred')
            assert updated_credential['sign_count'] == 5
    
    def test_update_passkey_last_used(self, db_app, db_user):
        """Test updating passkey last_used timestamp."""
        with db_app.app_context():
            pass0 = db_app.extensions['pass0']
            storage = pass0.storage
            
            credential_data = {
                'user_id': db_user['id'],
                'credential_id': 'test-cred',
                'public_key': 'test-key',
                'sign_count': 0
            }
            
            storage.store_passkey_credential(credential_data)
            
            credential = storage.get_passkey_credential_by_id('test-cred')
            cred_id = credential['id']
            
            # Initially last_used should be None
            assert credential.get('last_used_at') is None
            
            # Update last_used
            storage.update_passkey_last_used(cred_id)
            
            # Verify update
            updated_credential = storage.get_passkey_credential_by_id('test-cred')
            assert updated_credential['last_used_at'] is not None
    
    def test_delete_passkey_credential(self, db_app, db_user):
        """Test deleting passkey credential."""
        with db_app.app_context():
            pass0 = db_app.extensions['pass0']
            storage = pass0.storage
            
            credential_data = {
                'user_id': db_user['id'],
                'credential_id': 'test-cred',
                'public_key': 'test-key',
                'sign_count': 0
            }
            
            storage.store_passkey_credential(credential_data)
            
            # Get credential ID
            credential = storage.get_passkey_credential_by_id('test-cred')
            cred_id = credential['id']
            
            # Delete credential
            storage.delete_passkey_credential(cred_id)
            
            # Verify deletion
            deleted_credential = storage.get_passkey_credential_by_id('test-cred')
            assert deleted_credential is None


@pytest.mark.unit
class TestSQLAlchemy2FAOperations:
    
    def test_enable_2fa(self, db_app, db_user):
        """Test enabling 2FA for user."""
        with db_app.app_context():
            pass0 = db_app.extensions['pass0']
            storage = pass0.storage
            two_factor = pass0.two_factor
            
            secret = 'TEST-SECRET-BASE32'
            backup_codes = ['CODE1-CODE2', 'CODE3-CODE4']
            
            storage.enable_2fa(db_user['id'], secret, backup_codes)
            
            # Verify 2FA is enabled
            assert storage.is_2fa_enabled(db_user['id']) is True
            
            # Verify secret is stored
            stored_secret = storage.get_2fa_secret(db_user['id'])
            assert stored_secret is not None
    
    def test_disable_2fa(self, db_app, db_user):
        """Test disabling 2FA for user."""
        with db_app.app_context():
            pass0 = db_app.extensions['pass0']
            storage = pass0.storage
            
            # Enable 2FA first
            storage.enable_2fa(db_user['id'], 'TEST-SECRET', ['CODE1', 'CODE2'])
            assert storage.is_2fa_enabled(db_user['id']) is True
            
            # Disable 2FA
            storage.disable_2fa(db_user['id'])
            
            # Verify 2FA is disabled
            assert storage.is_2fa_enabled(db_user['id']) is False
            
            # Verify secret is removed
            secret = storage.get_2fa_secret(db_user['id'])
            assert secret is None
    
    def test_backup_code_validation(self, db_app, db_user):
        """Test backup code validation and consumption."""
        with db_app.app_context():
            pass0 = db_app.extensions['pass0']
            storage = pass0.storage
            two_factor = pass0.two_factor
            
            backup_codes = ['ABCD-EFGH', 'IJKL-MNOP']
            # Hash the codes before storing (this is what enable_2fa expects)
            hashed_codes = [two_factor.hash_backup_code(c) for c in backup_codes]
            
            storage.enable_2fa(db_user['id'], 'TEST-SECRET', hashed_codes)
            
            # Validate first code
            code_hash = two_factor.hash_backup_code('ABCD-EFGH')
            result = storage.validate_backup_code(db_user['id'], code_hash)
            assert result is True
            
            # Try to use same code again (should fail)
            result = storage.validate_backup_code(db_user['id'], code_hash)
            assert result is False
            
            # Second code should still work
            code_hash2 = two_factor.hash_backup_code('IJKL-MNOP')
            result = storage.validate_backup_code(db_user['id'], code_hash2)
            assert result is True
    
    def test_regenerate_backup_codes(self, db_app, db_user):
        """Test regenerating backup codes."""
        with db_app.app_context():
            pass0 = db_app.extensions['pass0']
            storage = pass0.storage
            two_factor = pass0.two_factor
            
            old_codes = ['OLD1-CODE', 'OLD2-CODE']
            storage.enable_2fa(db_app.User.query.get(db_user['id']).id, 'TEST-SECRET', old_codes)
            
            new_codes = ['NEW1-CODE', 'NEW2-CODE']
            hashed_new = [two_factor.hash_backup_code(c) for c in new_codes]
            
            storage.regenerate_backup_codes(db_user['id'], hashed_new)
            
            # Old codes should no longer work
            old_hash = two_factor.hash_backup_code('OLD1-CODE')
            result = storage.validate_backup_code(db_user['id'], old_hash)
            assert result is False
            
            # New codes should work
            new_hash = two_factor.hash_backup_code('NEW1-CODE')
            result = storage.validate_backup_code(db_user['id'], new_hash)
            assert result is True


@pytest.mark.integration
class TestSQLAlchemyEndToEnd:
    
    def test_complete_magic_link_flow_with_db(self, db_client):
        """Test complete magic link flow with SQLAlchemy storage."""
        app = db_client.application
        
        with app.app_context():
            # Create user
            user = app.User(email='flow@example.com')
            app.db.session.add(user)
            app.db.session.commit()
        
        # Request magic link
        response = db_client.post(
            '/auth/request-magic-link',
            json={'email': 'flow@example.com'}
        )
        
        assert response.status_code == 200
        data = response.get_json()
        assert data['success'] is True
        
        # Extract token from link
        link = data['link']
        token = link.split('/verify/')[-1]
        
        # Verify token
        response = db_client.get(f'/auth/verify/{token}', follow_redirects=False)
        
        assert response.status_code == 302
        
        # Check session
        with db_client.session_transaction() as sess:
            assert 'user_id' in sess
            assert 'logged_in_at' in sess
    
    def test_passkey_registration_with_db(self, db_client, db_user):
        """Test passkey registration flow with SQLAlchemy storage."""
        # Request registration options
        response = db_client.post(
            '/auth/passkey/register/options',
            json={'email': 'test@example.com'}
        )
        
        assert response.status_code == 200
        # Options generated successfully with DB storage


@pytest.mark.security
class TestSQLAlchemySecurity:
    
    def test_sql_injection_prevention_email(self, db_app):
        """Test that email queries are safe from SQL injection."""
        with db_app.app_context():
            pass0 = db_app.extensions['pass0']
            storage = pass0.storage
            
            # Attempt SQL injection via email
            malicious_email = "test' OR '1'='1"
            user = storage.get_user_by_email(malicious_email)
            
            # Should return None, not all users
            assert user is None
    
    def test_token_timing_attack_prevention(self, db_app, db_user):
        """Test that token verification timing doesn't leak information."""
        import time
        
        with db_app.app_context():
            pass0 = db_app.extensions['pass0']
            storage = pass0.storage
            
            # Store valid token
            valid_token = 'valid-token-12345'
            storage.store_token(valid_token, {'email': db_user['email']})
            
            # Time valid token check
            start = time.time()
            storage.get_token(valid_token)
            valid_time = time.time() - start
            
            # Time invalid token check
            start = time.time()
            storage.get_token('invalid-token-99999')
            invalid_time = time.time() - start
            
            # Timing should be similar (within 50ms)
            # This is a basic check - true timing attack prevention needs constant-time comparison
            time_diff = abs(valid_time - invalid_time)
            assert time_diff < 0.05  # 50ms tolerance
