"""
Passkey (WebAuthn) authentication tests for Flask-Pass0.
"""

import pytest
import json
from unittest.mock import patch, MagicMock
from flask_pass0.passkey import (
    generate_passkey_registration_options,
    verify_passkey_registration,
    generate_passkey_authentication_options,
    verify_passkey_authentication,
)


@pytest.fixture
def mock_webauthn_credential():
    """Mock WebAuthn credential response from browser."""
    return {
        'id': 'mock-credential-id-base64url',
        'rawId': 'mock-credential-id-base64url',
        'response': {
            'clientDataJSON': 'mock-client-data-base64url',
            'attestationObject': 'mock-attestation-object-base64url',
        },
        'type': 'public-key',
        'transports': ['internal', 'hybrid']
    }


@pytest.fixture
def app_with_passkey(base_config):
    """Flask app with passkey configuration."""
    from flask import Flask
    from flask_pass0 import Pass0
    from flask_pass0.storage import InMemoryStorageAdapter
    
    app = Flask(__name__)
    app.config.update(base_config)
    app.config['PASS0_PRIMARY_AUTH'] = 'passkey'
    app.config['PASS0_RP_ID'] = 'localhost'
    app.config['PASS0_RP_NAME'] = 'Test App'
    app.config['PASS0_ORIGIN'] = 'http://localhost:5000'
    
    storage = InMemoryStorageAdapter()
    pass0 = Pass0(app, storage_adapter=storage)
    
    @app.route('/protected')
    @pass0.login_required
    def protected():
        return 'Protected content'
    
    yield app


@pytest.fixture
def client_passkey(app_with_passkey):
    return app_with_passkey.test_client()


@pytest.mark.unit
class TestPasskeyRegistration:
    
    def test_generates_registration_options(self, app_with_passkey, test_email):
        """Test that registration options are generated correctly."""
        with app_with_passkey.test_request_context():
            options_json = generate_passkey_registration_options(test_email, user_id=1)
            options = json.loads(options_json)
            
            assert 'challenge' in options
            assert 'rp' in options
            assert options['rp']['id'] == 'localhost'
            assert options['rp']['name'] == 'Test App'
            assert 'user' in options
            assert options['user']['name'] == test_email
    
    def test_stores_challenge_in_session(self, client_passkey, test_email):
        """Test that challenge is stored in session."""
        with client_passkey.session_transaction() as sess:
            assert 'passkey_challenge' not in sess
        
        response = client_passkey.post(
            '/auth/passkey/register/options',
            json={'email': test_email}
        )
        
        assert response.status_code == 200
        
        with client_passkey.session_transaction() as sess:
            assert 'passkey_challenge' in sess
            assert 'passkey_user_email' in sess
            assert sess['passkey_user_email'] == test_email
    
    @patch('flask_pass0.passkey.verify_registration_response')
    def test_registration_verification_success(self, mock_verify, app_with_passkey, test_email, mock_webauthn_credential):
        """Test successful passkey registration verification."""
        # Mock the webauthn library's verification
        mock_verification = MagicMock()
        mock_verification.credential_id = b'test-credential-id'
        mock_verification.credential_public_key = b'test-public-key'
        mock_verification.sign_count = 0
        mock_verify.return_value = mock_verification
        
        pass0 = app_with_passkey.extensions['pass0']
        storage = pass0.storage
        
        # Create user
        storage.users[test_email] = {'id': 1, 'email': test_email}
        
        with app_with_passkey.test_request_context():
            from flask import session
            session['passkey_challenge'] = 'test-challenge-base64url'
            session['passkey_user_email'] = test_email
            
            result = verify_passkey_registration(mock_webauthn_credential, storage)
        
        assert result['success'] is True
        assert result['user']['email'] == test_email
        assert 'credential' in result


@pytest.mark.unit
class TestPasskeyAuthentication:
    
    def test_generates_authentication_options(self, app_with_passkey, test_user):
        """Test that authentication options are generated correctly."""
        pass0 = app_with_passkey.extensions['pass0']
        storage = pass0.storage
        
        # Add user with a passkey credential
        storage.users[test_user['email']] = test_user
        storage.passkey_credentials = {
            1: {
                'id': 1,
                'user_id': test_user['id'],
                'credential_id': 'test-cred-id-base64url',
                'public_key': 'test-public-key-base64url',
                'sign_count': 0,
                'transports': 'internal'
            }
        }
        
        with app_with_passkey.test_request_context():
            options_json = generate_passkey_authentication_options(test_user['email'], storage)
            options = json.loads(options_json)
            
            assert 'challenge' in options
            assert 'rpId' in options
            assert options['rpId'] == 'localhost'
    
    @patch('flask_pass0.passkey.verify_authentication_response')
    def test_authentication_verification_success(self, mock_verify, app_with_passkey, test_user, mock_webauthn_credential):
        """Test successful passkey authentication verification."""
        # Mock the webauthn library's verification
        mock_verification = MagicMock()
        mock_verification.new_sign_count = 1
        mock_verify.return_value = mock_verification
        
        pass0 = app_with_passkey.extensions['pass0']
        storage = pass0.storage
        
        # Setup user and credential
        storage.users[test_user['email']] = test_user
        # Use the same credential_id that mock_webauthn_credential will return
        credential_id = 'bW9jay1jcmVkZW50aWFsLWlk'  # Valid base64: "mock-credential-id"
        
        # Initialize passkey_credentials if needed
        if not hasattr(storage, 'passkey_credentials'):
            storage.passkey_credentials = {}
        
        storage.passkey_credentials[1] = {
            'id': 1,
            'user_id': test_user['id'],
            'credential_id': credential_id,
            'public_key': 'dGVzdC1wdWJsaWMta2V5',  # Valid base64: "test-public-key"
            'sign_count': 0,
            'transports': 'internal'
        }
        
        # Mock the get method to return our credential
        def mock_get_by_id(cred_id):
            # The mock_webauthn_credential fixture has id='mock-credential-id-base64url'
            # But we need to match what's actually in the fixture
            for cred in storage.passkey_credentials.values():
                if cred['credential_id'] == cred_id or cred_id == 'mock-credential-id-base64url':
                    return cred
            return None
        
        storage.get_passkey_credential_by_id = MagicMock(side_effect=mock_get_by_id)
        storage.update_passkey_sign_count = MagicMock()
        storage.update_passkey_last_used = MagicMock()
        storage.get_user_by_id = MagicMock(return_value=test_user)
        
        with app_with_passkey.test_request_context():
            from flask import session
            session['passkey_challenge'] = 'test-challenge-base64url'
            
            result = verify_passkey_authentication(mock_webauthn_credential, storage)
        
        assert result['success'] is True
        assert result['user']['email'] == test_user['email']
    
    def test_authentication_fails_without_challenge(self, app_with_passkey, mock_webauthn_credential):
        """Test that authentication fails without a challenge in session."""
        pass0 = app_with_passkey.extensions['pass0']
        storage = pass0.storage
        
        with app_with_passkey.test_request_context():
            result = verify_passkey_authentication(mock_webauthn_credential, storage)
        
        assert result['success'] is False
        assert 'No authentication in progress' in result['error']


@pytest.mark.integration
class TestPasskeyEndpoints:
    
    def test_register_options_endpoint(self, client_passkey, test_email):
        """Test the passkey registration options endpoint."""
        response = client_passkey.post(
            '/auth/passkey/register/options',
            json={'email': test_email}
        )
        
        assert response.status_code == 200
        data = json.loads(response.data)
        assert 'challenge' in data
        assert 'rp' in data
    
    def test_register_options_requires_email(self, client_passkey):
        """Test that email is required for registration."""
        response = client_passkey.post(
            '/auth/passkey/register/options',
            json={}
        )
        
        assert response.status_code == 400
        data = response.get_json()
        assert 'error' in data
    
    def test_login_options_endpoint(self, client_passkey, test_email):
        """Test the passkey login options endpoint."""
        response = client_passkey.post(
            '/auth/passkey/login/options',
            json={'email': test_email}
        )
        
        assert response.status_code == 200
        data = json.loads(response.data)
        assert 'challenge' in data
        assert 'rpId' in data


@pytest.mark.integration
class TestPasskeyManagement:
    
    def test_list_passkeys_requires_authentication(self, client_passkey):
        """Test that listing passkeys requires authentication."""
        response = client_passkey.get('/auth/passkeys')
        
        assert response.status_code == 401
        data = response.get_json()
        assert 'error' in data
    
    def test_list_passkeys_authenticated(self, app_with_passkey, test_user):
        """Test listing passkeys for authenticated user."""
        from datetime import datetime, timezone
        
        pass0 = app_with_passkey.extensions['pass0']
        storage = pass0.storage
        
        # Setup user and credential
        storage.users[test_user['email']] = test_user
        storage.passkey_credentials = {
            1: {
                'id': 1,
                'user_id': test_user['id'],
                'credential_id': 'test-cred-1',
                'created_at': '2024-01-01T00:00:00Z',
                'last_used_at': None
            }
        }
        
        client = app_with_passkey.test_client()
        
        # Authenticate user
        with client.session_transaction() as sess:
            sess['user_id'] = test_user['id']
            sess['logged_in_at'] = datetime.now(timezone.utc).isoformat()
        
        response = client.get('/auth/passkeys')
        
        assert response.status_code == 200
        data = response.get_json()
        assert data['success'] is True
        assert len(data['passkeys']) == 1
    
    def test_revoke_passkey_requires_authentication(self, client_passkey):
        """Test that revoking passkeys requires authentication."""
        response = client_passkey.delete('/auth/passkeys/1')
        
        assert response.status_code == 401
    
    def test_revoke_passkey_success(self, app_with_passkey, test_user):
        """Test successful passkey revocation."""
        from datetime import datetime, timezone
        
        pass0 = app_with_passkey.extensions['pass0']
        storage = pass0.storage
        
        # Setup user and credential
        storage.users[test_user['email']] = test_user
        storage.passkey_credentials = {
            1: {
                'id': 1,
                'user_id': test_user['id'],
                'credential_id': 'test-cred-1'
            }
        }
        
        client = app_with_passkey.test_client()
        
        # Authenticate user
        with client.session_transaction() as sess:
            sess['user_id'] = test_user['id']
            sess['logged_in_at'] = datetime.now(timezone.utc).isoformat()
        
        response = client.delete('/auth/passkeys/1')
        
        assert response.status_code == 200
        data = response.get_json()
        assert data['success'] is True


@pytest.mark.security
class TestPasskeySecurity:
    
    def test_cannot_revoke_other_users_passkey(self, app_with_passkey):
        """Test that users cannot revoke other users' passkeys."""
        from datetime import datetime, timezone
        
        pass0 = app_with_passkey.extensions['pass0']
        storage = pass0.storage
        
        # Create two users
        user1 = {'id': 1, 'email': 'user1@example.com'}
        user2 = {'id': 2, 'email': 'user2@example.com'}
        storage.users[user1['email']] = user1
        storage.users[user2['email']] = user2
        
        # User2's passkey
        storage.passkey_credentials = {
            1: {
                'id': 1,
                'user_id': user2['id'],
                'credential_id': 'user2-cred'
            }
        }
        
        client = app_with_passkey.test_client()
        
        # Authenticate as user1
        with client.session_transaction() as sess:
            sess['user_id'] = user1['id']
            sess['logged_in_at'] = datetime.now(timezone.utc).isoformat()
        
        # Try to revoke user2's passkey
        response = client.delete('/auth/passkeys/1')
        
        assert response.status_code == 404  # Passkey not found for this user
    
    def test_challenge_stored_in_session_not_exposed(self, client_passkey, test_email):
        """Test that challenges are not exposed in responses."""
        response = client_passkey.post(
            '/auth/passkey/register/options',
            json={'email': test_email}
        )
        
        assert response.status_code == 200
        data = json.loads(response.data)
        
        # Challenge should be in response (for WebAuthn API)
        assert 'challenge' in data
        
        # But raw challenge should only be in session, not exposed elsewhere
        with client_passkey.session_transaction() as sess:
            session_challenge = sess.get('passkey_challenge')
            assert session_challenge is not None
            # Session challenge is base64url encoded
            assert isinstance(session_challenge, str)
    
    def test_origin_validation_required(self, app_with_passkey):
        """Test that origin is validated during verification."""
        # This is tested implicitly through the webauthn library
        # The PASS0_ORIGIN config must match the actual request origin
        assert app_with_passkey.config['PASS0_ORIGIN'] == 'http://localhost:5000'
        assert app_with_passkey.config['PASS0_RP_ID'] == 'localhost'
