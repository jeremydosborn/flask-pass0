"""
Two-Factor Authentication (2FA) tests for Flask-Pass0.
"""

import pytest
import pyotp
from datetime import datetime, timezone


@pytest.mark.unit
class TestTOTPGeneration:
    
    def test_generates_totp_secret(self, app_with_2fa):
        """Test TOTP secret generation."""
        pass0 = app_with_2fa.extensions['pass0']
        two_factor = pass0.two_factor
        
        secret = two_factor.generate_totp_secret()
        
        assert secret is not None
        assert len(secret) == 32  # Base32 encoded
        assert secret.isalnum()
        assert secret.isupper()
    
    def test_totp_uri_generation(self, app_with_2fa, test_email):
        """Test TOTP provisioning URI generation."""
        with app_with_2fa.app_context():
            pass0 = app_with_2fa.extensions['pass0']
            two_factor = pass0.two_factor
            
            secret = two_factor.generate_totp_secret()
            uri = two_factor.get_totp_uri(test_email, secret)
            
            assert uri.startswith('otpauth://totp/')
            # URL encoding may occur - check both formats
            assert test_email in uri or test_email.replace('@', '%40') in uri
            assert 'Test App' in uri or 'Test%20App' in uri
            assert secret in uri
    
    def test_qr_code_generation(self, app_with_2fa, test_email):
        """Test QR code image generation."""
        with app_with_2fa.app_context():
            pass0 = app_with_2fa.extensions['pass0']
            two_factor = pass0.two_factor
            
            secret = two_factor.generate_totp_secret()
            uri = two_factor.get_totp_uri(test_email, secret)
            qr_code = two_factor.generate_qr_code(uri)
            
            assert qr_code.startswith('data:image/png;base64,')
            assert len(qr_code) > 100  # Should be a substantial base64 string


@pytest.mark.unit
class TestTOTPVerification:
    
    def test_verifies_valid_totp_code(self, app_with_2fa):
        """Test TOTP code verification with valid code."""
        pass0 = app_with_2fa.extensions['pass0']
        two_factor = pass0.two_factor
        
        secret = two_factor.generate_totp_secret()
        totp = pyotp.TOTP(secret)
        valid_code = totp.now()
        
        assert two_factor.verify_totp_code(secret, valid_code) is True
    
    def test_rejects_invalid_totp_code(self, app_with_2fa):
        """Test TOTP code verification with invalid code."""
        pass0 = app_with_2fa.extensions['pass0']
        two_factor = pass0.two_factor
        
        secret = two_factor.generate_totp_secret()
        
        assert two_factor.verify_totp_code(secret, '000000') is False
        assert two_factor.verify_totp_code(secret, '123456') is False
    
    def test_rejects_empty_code(self, app_with_2fa):
        """Test TOTP verification rejects empty codes."""
        pass0 = app_with_2fa.extensions['pass0']
        two_factor = pass0.two_factor
        
        secret = two_factor.generate_totp_secret()
        
        assert two_factor.verify_totp_code(secret, '') is False
        assert two_factor.verify_totp_code(secret, None) is False


@pytest.mark.unit
class TestBackupCodes:
    
    def test_generates_backup_codes(self, app_with_2fa):
        """Test backup code generation."""
        pass0 = app_with_2fa.extensions['pass0']
        two_factor = pass0.two_factor
        
        codes = two_factor.generate_backup_codes(count=8)
        
        assert len(codes) == 8
        for code in codes:
            assert '-' in code  # Format: XXXX-XXXX
            clean = code.replace('-', '')
            assert len(clean) == 8
            assert clean.isalnum()
    
    def test_backup_codes_are_unique(self, app_with_2fa):
        """Test that backup codes are all unique."""
        pass0 = app_with_2fa.extensions['pass0']
        two_factor = pass0.two_factor
        
        codes = two_factor.generate_backup_codes(count=10)
        
        assert len(codes) == len(set(codes))  # All unique
    
    def test_backup_code_hashing(self, app_with_2fa):
        """Test backup codes are hashed before storage."""
        pass0 = app_with_2fa.extensions['pass0']
        two_factor = pass0.two_factor
        
        code = 'ABCD-EFGH'
        code_hash = two_factor.hash_backup_code(code)
        
        # Should be a SHA-256 hex hash
        assert len(code_hash) == 64
        assert all(c in '0123456789abcdef' for c in code_hash)
        
        # Should not contain original code
        assert 'ABCD' not in code_hash
        assert 'EFGH' not in code_hash
    
    def test_backup_code_case_insensitive(self, app_with_2fa):
        """Test backup code hashing is case insensitive."""
        pass0 = app_with_2fa.extensions['pass0']
        two_factor = pass0.two_factor
        
        hash1 = two_factor.hash_backup_code('ABCD-EFGH')
        hash2 = two_factor.hash_backup_code('abcd-efgh')
        hash3 = two_factor.hash_backup_code('AbCd-EfGh')
        
        assert hash1 == hash2 == hash3


@pytest.mark.integration
class Test2FASetup:
    
    def test_setup_2fa_generates_qr_code(self, client_2fa, test_user):
        """Test 2FA setup returns QR code and secret."""
        app = client_2fa.application
        
        # Create user in storage first
        with app.app_context():
            pass0 = app.extensions['pass0']
            storage = pass0.storage
            storage.users[test_user['email']] = test_user
        
        # Authenticate user
        with client_2fa.session_transaction() as sess:
            sess['user_id'] = test_user['id']
            sess['logged_in_at'] = datetime.now(timezone.utc).isoformat()
        
        response = client_2fa.get('/auth/2fa/setup')
        
        assert response.status_code == 200
        data = response.get_json()
        assert 'qr_code' in data
        assert 'secret' in data
        assert 'uri' in data
        assert data['qr_code'].startswith('data:image/png;base64,')
    
    def test_setup_2fa_requires_authentication(self, client_2fa):
        """Test 2FA setup requires authenticated user."""
        response = client_2fa.get('/auth/2fa/setup')
        
        # Should redirect to login
        assert response.status_code == 302
        assert '/auth/login' in response.location
    
    def test_enable_2fa_with_valid_code(self, client_2fa, test_user):
        """Test enabling 2FA with valid TOTP code."""
        app = client_2fa.application
        pass0 = app.extensions['pass0']
        two_factor = pass0.two_factor
        
        # Create user in storage first
        with app.app_context():
            storage = pass0.storage
            storage.users[test_user['email']] = test_user
        
        # Authenticate user
        with client_2fa.session_transaction() as sess:
            sess['user_id'] = test_user['id']
            sess['logged_in_at'] = datetime.now(timezone.utc).isoformat()
        
        # Get setup info
        response = client_2fa.get('/auth/2fa/setup')
        data = response.get_json()
        secret = data['secret']
        
        # Generate valid code
        totp = pyotp.TOTP(secret)
        valid_code = totp.now()
        
        # Enable 2FA
        response = client_2fa.post(
            '/auth/2fa/setup',
            json={'code': valid_code}
        )
        
        assert response.status_code == 200
        data = response.get_json()
        assert data['success'] is True
        assert 'backup_codes' in data
        assert len(data['backup_codes']) == 8
    
    def test_enable_2fa_rejects_invalid_code(self, client_2fa, test_user):
        """Test enabling 2FA fails with invalid code."""
        app = client_2fa.application
        
        # Create user in storage first
        with app.app_context():
            pass0 = app.extensions['pass0']
            storage = pass0.storage
            storage.users[test_user['email']] = test_user
        
        # Authenticate user
        with client_2fa.session_transaction() as sess:
            sess['user_id'] = test_user['id']
            sess['logged_in_at'] = datetime.now(timezone.utc).isoformat()
        
        # Get setup info
        client_2fa.get('/auth/2fa/setup')
        
        # Try to enable with invalid code
        response = client_2fa.post(
            '/auth/2fa/setup',
            json={'code': '000000'}
        )
        
        assert response.status_code == 400
        data = response.get_json()
        assert 'error' in data


@pytest.mark.integration
class Test2FAVerification:
    
    def test_2fa_required_after_magic_link(self, client_2fa, test_user):
        """Test that 2FA is required after magic link login when enabled."""
        app = client_2fa.application
        pass0 = app.extensions['pass0']
        storage = pass0.storage
        two_factor = pass0.two_factor
        
        # Setup user with 2FA enabled
        storage.users[test_user['email']] = test_user
        secret = two_factor.generate_totp_secret()
        backup_codes = two_factor.generate_backup_codes()
        two_factor.enable_2fa(test_user['id'], secret, backup_codes)
        
        # Request magic link
        with app.test_request_context():
            from flask_pass0.magic_link import generate_magic_link
            link = generate_magic_link(test_user['email'], storage=storage)
            token = link.split('/verify/')[-1]
        
        # Verify magic link
        response = client_2fa.get(f'/auth/verify/{token}', follow_redirects=False)
        
        # Should redirect to 2FA verification, not dashboard
        assert response.status_code == 302
        assert 'verify-2fa' in response.location
        
        # Session should have 2fa_pending flag
        with client_2fa.session_transaction() as sess:
            assert sess.get('2fa_pending') is True
    
    def test_verify_2fa_with_valid_totp(self, client_2fa, test_user):
        """Test 2FA verification with valid TOTP code."""
        app = client_2fa.application
        pass0 = app.extensions['pass0']
        storage = pass0.storage
        two_factor = pass0.two_factor
        
        # Setup user with 2FA
        storage.users[test_user['email']] = test_user
        secret = two_factor.generate_totp_secret()
        backup_codes = two_factor.generate_backup_codes()
        two_factor.enable_2fa(test_user['id'], secret, backup_codes)
        
        # Simulate pending 2FA state
        with client_2fa.session_transaction() as sess:
            sess['user_id'] = test_user['id']
            sess['2fa_pending'] = True
        
        # Generate valid code
        totp = pyotp.TOTP(secret)
        valid_code = totp.now()
        
        # Verify 2FA
        response = client_2fa.post(
            '/auth/2fa/verify',
            json={'code': valid_code}
        )
        
        assert response.status_code == 200
        data = response.get_json()
        assert data['success'] is True
        
        # 2fa_pending should be cleared
        with client_2fa.session_transaction() as sess:
            assert sess.get('2fa_pending') is None
            assert 'logged_in_at' in sess
    
    def test_verify_2fa_with_backup_code(self, client_2fa, test_user):
        """Test 2FA verification with backup code."""
        app = client_2fa.application
        pass0 = app.extensions['pass0']
        storage = pass0.storage
        two_factor = pass0.two_factor
        
        # Setup user with 2FA
        storage.users[test_user['email']] = test_user
        secret = two_factor.generate_totp_secret()
        backup_codes = two_factor.generate_backup_codes()
        two_factor.enable_2fa(test_user['id'], secret, backup_codes)
        
        # Simulate pending 2FA state
        with client_2fa.session_transaction() as sess:
            sess['user_id'] = test_user['id']
            sess['2fa_pending'] = True
        
        # Verify with backup code
        response = client_2fa.post(
            '/auth/2fa/verify',
            json={
                'code': backup_codes[0],
                'use_backup': True
            }
        )
        
        assert response.status_code == 200
        data = response.get_json()
        assert data['success'] is True
    
    def test_verify_2fa_rejects_invalid_code(self, client_2fa, test_user):
        """Test 2FA verification fails with invalid code."""
        app = client_2fa.application
        pass0 = app.extensions['pass0']
        storage = pass0.storage
        two_factor = pass0.two_factor
        
        # Setup user with 2FA
        storage.users[test_user['email']] = test_user
        secret = two_factor.generate_totp_secret()
        backup_codes = two_factor.generate_backup_codes()
        two_factor.enable_2fa(test_user['id'], secret, backup_codes)
        
        # Simulate pending 2FA state
        with client_2fa.session_transaction() as sess:
            sess['user_id'] = test_user['id']
            sess['2fa_pending'] = True
        
        # Try invalid code
        response = client_2fa.post(
            '/auth/2fa/verify',
            json={'code': '000000'}
        )
        
        assert response.status_code == 400
        data = response.get_json()
        assert 'error' in data


@pytest.mark.integration
class Test2FAManagement:
    
    def test_disable_2fa(self, client_2fa, test_user):
        """Test disabling 2FA."""
        app = client_2fa.application
        pass0 = app.extensions['pass0']
        storage = pass0.storage
        two_factor = pass0.two_factor
        
        # Setup user with 2FA
        storage.users[test_user['email']] = test_user
        secret = two_factor.generate_totp_secret()
        backup_codes = two_factor.generate_backup_codes()
        two_factor.enable_2fa(test_user['id'], secret, backup_codes)
        
        # Authenticate user
        with client_2fa.session_transaction() as sess:
            sess['user_id'] = test_user['id']
            sess['logged_in_at'] = datetime.now(timezone.utc).isoformat()
        
        # Verify 2FA is enabled
        assert two_factor.is_2fa_enabled(test_user['id']) is True
        
        # Disable 2FA
        response = client_2fa.post('/auth/2fa/disable')
        
        assert response.status_code == 200
        data = response.get_json()
        assert data['success'] is True
        
        # Verify 2FA is disabled
        assert two_factor.is_2fa_enabled(test_user['id']) is False
    
    def test_regenerate_backup_codes(self, client_2fa, test_user):
        """Test regenerating backup codes."""
        app = client_2fa.application
        pass0 = app.extensions['pass0']
        storage = pass0.storage
        two_factor = pass0.two_factor
        
        # Setup user with 2FA
        storage.users[test_user['email']] = test_user
        secret = two_factor.generate_totp_secret()
        old_codes = two_factor.generate_backup_codes()
        two_factor.enable_2fa(test_user['id'], secret, old_codes)
        
        # Authenticate user
        with client_2fa.session_transaction() as sess:
            sess['user_id'] = test_user['id']
            sess['logged_in_at'] = datetime.now(timezone.utc).isoformat()
        
        # Regenerate codes
        response = client_2fa.post('/auth/2fa/backup-codes')
        
        assert response.status_code == 200
        data = response.get_json()
        assert data['success'] is True
        assert 'backup_codes' in data
        
        new_codes = data['backup_codes']
        assert len(new_codes) == 8
        
        # New codes should be different from old codes
        assert set(new_codes) != set(old_codes)
    
    def test_2fa_operations_require_authentication(self, client_2fa):
        """Test that 2FA management requires authentication."""
        # Disable without auth
        response = client_2fa.post('/auth/2fa/disable')
        assert response.status_code == 401
        
        # Regenerate codes without auth
        response = client_2fa.post('/auth/2fa/backup-codes')
        assert response.status_code == 401


@pytest.mark.security
class Test2FASecurity:
    
    def test_totp_secret_not_exposed_in_responses(self, client_2fa, test_user):
        """Test that TOTP secrets are never exposed in API responses."""
        app = client_2fa.application
        
        # Create user in storage first
        with app.app_context():
            pass0 = app.extensions['pass0']
            storage = pass0.storage
            storage.users[test_user['email']] = test_user
        
        # Authenticate user
        with client_2fa.session_transaction() as sess:
            sess['user_id'] = test_user['id']
            sess['logged_in_at'] = datetime.now(timezone.utc).isoformat()
        
        # Setup returns secret (intentional, for QR code generation)
        response = client_2fa.get('/auth/2fa/setup')
        data = response.get_json()
        secret = data['secret']
        
        # But after enabling, secret should not be in any response
        totp = pyotp.TOTP(secret)
        valid_code = totp.now()
        
        response = client_2fa.post('/auth/2fa/setup', json={'code': valid_code})
        data = response.get_json()
        
        # Should have backup codes but NOT secret
        assert 'backup_codes' in data
        assert 'secret' not in data
    
    def test_backup_codes_consumed_after_use(self, client_2fa, test_user):
        """Test that backup codes can only be used once."""
        app = client_2fa.application
        pass0 = app.extensions['pass0']
        storage = pass0.storage
        two_factor = pass0.two_factor
        
        # Setup user with 2FA
        storage.users[test_user['email']] = test_user
        secret = two_factor.generate_totp_secret()
        backup_codes = two_factor.generate_backup_codes()
        two_factor.enable_2fa(test_user['id'], secret, backup_codes)
        
        backup_code = backup_codes[0]
        
        # First use should succeed
        with client_2fa.session_transaction() as sess:
            sess['user_id'] = test_user['id']
            sess['2fa_pending'] = True
        
        response = client_2fa.post(
            '/auth/2fa/verify',
            json={'code': backup_code, 'use_backup': True}
        )
        assert response.status_code == 200
        
        # Second use of same code should fail
        with client_2fa.session_transaction() as sess:
            sess['user_id'] = test_user['id']
            sess['2fa_pending'] = True
        
        response = client_2fa.post(
            '/auth/2fa/verify',
            json={'code': backup_code, 'use_backup': True}
        )
        assert response.status_code == 400
    
    def test_session_temp_data_cleared_after_2fa_setup(self, client_2fa, test_user):
        """Test that temporary session data is cleared after 2FA setup."""
        app = client_2fa.application
        
        # Create user in storage first
        with app.app_context():
            pass0 = app.extensions['pass0']
            storage = pass0.storage
            storage.users[test_user['email']] = test_user
        
        # Authenticate user
        with client_2fa.session_transaction() as sess:
            sess['user_id'] = test_user['id']
            sess['logged_in_at'] = datetime.now(timezone.utc).isoformat()
        
        # Start setup
        response = client_2fa.get('/auth/2fa/setup')
        data = response.get_json()
        secret = data['secret']
        
        # temp_totp_secret should be in session during setup
        with client_2fa.session_transaction() as sess:
            assert 'temp_totp_secret' in sess
        
        # Complete setup
        totp = pyotp.TOTP(secret)
        valid_code = totp.now()
        client_2fa.post('/auth/2fa/setup', json={'code': valid_code})
        
        # temp_totp_secret should be cleared after completion
        with client_2fa.session_transaction() as sess:
            assert 'temp_totp_secret' not in sess
