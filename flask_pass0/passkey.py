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


def generate_passkey_registration_options(user_email, user_id):
    """
    Generate WebAuthn registration options for a user.
    
    Args:
        user_email: User's email address
        user_id: User's database ID
        
    Returns:
        dict: Registration options to send to frontend
    """
    rp_id = current_app.config.get('PASS0_RP_ID', 'localhost')
    rp_name = current_app.config.get('PASS0_RP_NAME', 'Flask-Pass0')
    
    # Generate challenge
    challenge = secrets.token_bytes(32)
    
    # Store challenge in session for verification
    session['passkey_challenge'] = bytes_to_base64url(challenge)
    session['passkey_user_email'] = user_email
    
    options = generate_registration_options(
        rp_id=rp_id,
        rp_name=rp_name,
        user_id=str(user_id).encode('utf-8'),
        user_name=user_email,
        user_display_name=user_email,
        challenge=challenge,
        authenticator_selection=AuthenticatorSelectionCriteria(
            authenticator_attachment=AuthenticatorAttachment.PLATFORM,
            resident_key=ResidentKeyRequirement.REQUIRED,
            user_verification=UserVerificationRequirement.REQUIRED
        ),
        timeout=60000,  # 60 seconds
    )
    
    return options_to_json(options)


def verify_passkey_registration(credential_response, storage):
    """
    Verify passkey registration response from browser.
    
    Args:
        credential_response: JSON response from browser
        storage: Storage adapter
        
    Returns:
        dict: {'success': bool, 'user': dict, 'credential': dict, 'error': str}
    """
    # Get stored challenge
    challenge = session.get('passkey_challenge')
    user_email = session.get('passkey_user_email')
    
    if not challenge or not user_email:
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
        
        # Get or create user
        user = storage.get_user_by_email(user_email)
        if not user:
            user = storage.get_or_create_user(user_email)
        
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
        session.pop('passkey_user_email', None)
        
        return {
            'success': True,
            'user': user,
            'credential': credential_data
        }
        
    except Exception as e:
        current_app.logger.error(f"Passkey registration verification failed: {str(e)}")
        return {'success': False, 'error': str(e)}


def generate_passkey_authentication_options(user_email, storage):
    """
    Generate WebAuthn authentication options.
    
    Args:
        user_email: User's email address (optional, can be None for usernameless)
        storage: Storage adapter
        
    Returns:
        dict: Authentication options to send to frontend
    """
    rp_id = current_app.config.get('PASS0_RP_ID', 'localhost')
    
    # Generate challenge
    challenge = secrets.token_bytes(32)
    
    # Store challenge in session
    session['passkey_challenge'] = bytes_to_base64url(challenge)
    if user_email:
        session['passkey_user_email'] = user_email
    
    # Get user's registered credentials if email provided
    allow_credentials = []
    if user_email:
        user = storage.get_user_by_email(user_email)
        if user:
            credentials = storage.get_passkey_credentials(user['id'])
            allow_credentials = [
                PublicKeyCredentialDescriptor(
                    id=base64url_to_bytes(cred['credential_id']),
                    transports=[
                        AuthenticatorTransport(t.strip()) 
                        for t in cred.get('transports', '').split(',') 
                        if t.strip()
                    ] if cred.get('transports') else None
                )
                for cred in credentials
            ]
    
    options = generate_authentication_options(
        rp_id=rp_id,
        challenge=challenge,
        allow_credentials=allow_credentials if allow_credentials else None,
        user_verification=UserVerificationRequirement.PREFERRED,
        timeout=60000,
    )
    
    return options_to_json(options)


def verify_passkey_authentication(credential_response, storage):
    """
    Verify passkey authentication response from browser.
    
    Args:
        credential_response: JSON response from browser
        storage: Storage adapter
        
    Returns:
        dict: {'success': bool, 'user': dict, 'error': str}
    """
    # Get stored challenge
    challenge = session.get('passkey_challenge')
    
    if not challenge:
        return {'success': False, 'error': 'No authentication in progress'}
    
    rp_id = current_app.config.get('PASS0_RP_ID', 'localhost')
    origin = current_app.config.get('PASS0_ORIGIN', 'http://localhost:5000')
    
    try:
        # Get credential_id from response
        credential_id = credential_response.get('id')
        if not credential_id:
            credential_id = credential_response.get('rawId')
        
        # Look up credential in database
        credential = storage.get_passkey_credential_by_id(credential_id)
        if not credential:
            return {'success': False, 'error': 'Credential not found'}
        
        # Get user
        user = storage.get_user_by_id(credential['user_id'])
        if not user:
            return {'success': False, 'error': 'User not found'}
        
        # Verify the authentication
        verification = verify_authentication_response(
            credential=credential_response,
            expected_challenge=base64url_to_bytes(challenge),
            expected_rp_id=rp_id,
            expected_origin=origin,
            credential_public_key=base64url_to_bytes(credential['public_key']),
            credential_current_sign_count=credential['sign_count'],
        )
        
        # Update sign count
        storage.update_passkey_sign_count(
            credential['id'],
            verification.new_sign_count
        )
        
        # Update last used
        storage.update_passkey_last_used(credential['id'])
        
        # Clear session
        session.pop('passkey_challenge', None)
        session.pop('passkey_user_email', None)
        
        return {
            'success': True,
            'user': user
        }
        
    except Exception as e:
        current_app.logger.error(f"Passkey authentication verification failed: {str(e)}")
        return {'success': False, 'error': str(e)}