"""WebAuthn passkey authentication."""
from webauthn import (
    generate_registration_options,
    verify_registration_response,
    generate_authentication_options,
    verify_authentication_response,
    options_to_json,
)

from webauthn.helpers.structs import (
    AuthenticatorSelectionCriteria,
    UserVerificationRequirement,
    PublicKeyCredentialDescriptor,
    AuthenticatorTransport,
    AuthenticatorAttachment,      # ADD THIS
    ResidentKeyRequirement,        # ADD THIS
)

from webauthn.helpers import base64url_to_bytes, bytes_to_base64url
from flask import current_app, session
from datetime import datetime, timezone
import secrets


def generate_passkey_registration_options():
    """
    Generate WebAuthn registration options for a new passkey.
    No email required - user will be created upon successful registration.
    
    Returns:
        dict: Registration options to send to frontend
    """
    rp_id = current_app.config.get('PASS0_RP_ID', 'localhost')
    rp_name = current_app.config.get('PASS0_RP_NAME', 'Flask-Pass0')
    
    # Generate challenge
    challenge = secrets.token_bytes(32)
    
    # Generate a temporary user identifier for this registration
    temp_user_id = secrets.token_hex(16)
    
    # Store challenge and temp ID in session for verification
    session['passkey_challenge'] = bytes_to_base64url(challenge)
    session['passkey_temp_user_id'] = temp_user_id
    
    options = generate_registration_options(
        rp_id=rp_id,
        rp_name=rp_name,
        user_id=temp_user_id.encode('utf-8'),
        user_name=f"user_{temp_user_id[:8]}",
        user_display_name="Passkey User",
        challenge=challenge,
        authenticator_selection=AuthenticatorSelectionCriteria(
            authenticator_attachment=AuthenticatorAttachment.PLATFORM,
            resident_key=ResidentKeyRequirement.REQUIRED,
            user_verification=UserVerificationRequirement.REQUIRED
        ),
        timeout=60000,
    )
    
    return options_to_json(options)


def verify_passkey_registration(credential_response, storage):
    """
    Verify passkey registration response from browser.
    Creates a new user without email.
    
    Args:
        credential_response: JSON response from browser
        storage: Storage adapter
        
    Returns:
        dict: {'success': bool, 'user': dict, 'credential': dict, 'error': str}
    """
    # Get stored challenge
    challenge = session.get('passkey_challenge')
    temp_user_id = session.get('passkey_temp_user_id')
    
    if not challenge or not temp_user_id:
        return {'success': False, 'error': 'No registration in progress'}
    
    rp_id = current_app.config.get('PASS0_RP_ID', 'localhost')
    origin = current_app.config.get('PASS0_ORIGIN', 'http://localhost:5000')
    
    try:
        verification = verify_registration_response(
            credential=credential_response,
            expected_challenge=base64url_to_bytes(challenge),
            expected_rp_id=rp_id,
            expected_origin=origin,
        )
        
        # Create user without email (email can be None/null in DB)
        user = storage.get_or_create_user(email=None)
        
        # Store credential
        credential_data = {
            'user_id': user['id'],
            'credential_id': bytes_to_base64url(verification.credential_id),
            'public_key': bytes_to_base64url(verification.credential_public_key),
            'sign_count': verification.sign_count,
            'transports': ','.join(credential_response.get('transports', [])) if credential_response.get('transports') else None,
        }
        
        storage.store_passkey_credential(credential_data)
        
        # Clear session
        session.pop('passkey_challenge', None)
        session.pop('passkey_temp_user_id', None)
        
        return {
            'success': True,
            'user': user,
            'credential': credential_data
        }
        
    except Exception as e:
        current_app.logger.error(f"Passkey registration verification failed: {str(e)}")
        return {'success': False, 'error': str(e)}

def generate_passkey_authentication_options(storage):
    """
    Generate WebAuthn authentication options.
    Discoverable credentials (passkeys), no QR, no email.
    """
    rp_id = current_app.config.get('PASS0_RP_ID', 'localhost')

    challenge = secrets.token_bytes(32)
    session['passkey_challenge'] = bytes_to_base64url(challenge)

    options = generate_authentication_options(
        rp_id=rp_id,
        challenge=challenge,
        allow_credentials=[],  # ✅ MUST be a sequence
        user_verification=UserVerificationRequirement.REQUIRED,
        timeout=60000,
    )

    return options_to_json(options)

def verify_passkey_authentication(credential_response, storage):
    """
    Verify passkey authentication response from browser.
    Uses rawId (canonical) for credential lookup.
    """

    # ---- Challenge check ----
    challenge_b64 = session.pop('passkey_challenge', None)
    if not challenge_b64:
        return {'success': False, 'error': 'No authentication in progress'}

    rp_id = current_app.config.get('PASS0_RP_ID', 'localhost')
    origin = current_app.config.get('PASS0_ORIGIN', 'http://localhost:5000')

    try:
        # ---- ALWAYS use rawId (canonical WebAuthn identifier) ----
        raw_id_b64 = credential_response.get('rawId')
        if not raw_id_b64:
            return {'success': False, 'error': 'Missing rawId'}

        # Normalize to the exact format stored during registration
        credential_id = bytes_to_base64url(base64url_to_bytes(raw_id_b64))

        # ---- Lookup credential ----
        credential = storage.get_passkey_credential_by_id(credential_id)
        if not credential:
            return {'success': False, 'error': 'Credential not found'}

        # ---- Verify assertion cryptographically ----
        verification = verify_authentication_response(
            credential=credential_response,
            expected_challenge=base64url_to_bytes(challenge_b64),
            expected_rp_id=rp_id,
            expected_origin=origin,
            credential_public_key=base64url_to_bytes(credential['public_key']),
            credential_current_sign_count=credential['sign_count'],
        )

        # ---- Update counters ----
        storage.update_passkey_sign_count(
            credential['id'],
            verification.new_sign_count
        )
        storage.update_passkey_last_used(credential['id'])

        # ---- Load user ----
        user = storage.get_user_by_id(credential['user_id'])
        if not user:
            return {'success': False, 'error': 'User not found'}

        return {
            'success': True,
            'user': user
        }

    except Exception as e:
        current_app.logger.error(f"Passkey authentication failed: {e}")
        return {'success': False, 'error': str(e)}