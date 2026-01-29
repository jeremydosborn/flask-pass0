import secrets
from flask import current_app
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
    AuthenticatorAttachment,
    ResidentKeyRequirement,
)
from webauthn.helpers import base64url_to_bytes, bytes_to_base64url


class Passkey:
    """WebAuthn passkey authentication primitives."""

    def __init__(self, storage):
        self.storage = storage

    def registration_options(self, user_id=None, user_name=None, rp_id=None, rp_name=None):
        """
        Generate WebAuthn registration options.

        Returns dict with 'options' (JSON string for browser), 'challenge' (store for verify),
        and 'user_handle' (internal user identifier).
        """
        rp_id = rp_id or current_app.config.get("PASS0_RP_ID", "localhost")
        rp_name = rp_name or current_app.config.get("PASS0_RP_NAME", "Flask-Pass0")
        challenge = secrets.token_bytes(32)
        user_handle = str(user_id) if user_id else secrets.token_hex(16)

        options = generate_registration_options(
            rp_id=rp_id,
            rp_name=rp_name,
            user_id=user_handle.encode("utf-8"),
            user_name=user_name or f"user_{user_handle[:8]}",
            user_display_name=user_name or "Passkey User",
            challenge=challenge,
            authenticator_selection=AuthenticatorSelectionCriteria(
                authenticator_attachment=AuthenticatorAttachment.PLATFORM,
                resident_key=ResidentKeyRequirement.REQUIRED,
                user_verification=UserVerificationRequirement.REQUIRED,
            ),
            timeout=60000,
        )

        return {
            "options": options_to_json(options),
            "challenge": bytes_to_base64url(challenge),
            "user_handle": user_handle,
        }

    def verify_registration(self, credential, challenge, user_id=None, rp_id=None, origin=None):
        """
        Verify passkey registration response.

        If user_id is provided, adds passkey to existing user.
        Otherwise creates a new user.

        Returns dict with 'success', 'user', 'credential_id', or 'error'.
        """
        rp_id = rp_id or current_app.config.get("PASS0_RP_ID", "localhost")
        origin = origin or current_app.config.get("PASS0_ORIGIN", "http://localhost:5000")

        try:
            verification = verify_registration_response(
                credential=credential,
                expected_challenge=base64url_to_bytes(challenge),
                expected_rp_id=rp_id,
                expected_origin=origin,
            )

            if user_id:
                user = self.storage.get_user_by_id(user_id)
                if not user:
                    return {"success": False, "error": "User not found"}
            else:
                user = self.storage.create_user()

            credential_id = bytes_to_base64url(verification.credential_id)
            transports = credential.get("transports")

            self.storage.store_passkey_credential({
                "user_id": user["id"],
                "credential_id": credential_id,
                "public_key": bytes_to_base64url(verification.credential_public_key),
                "sign_count": verification.sign_count,
                "transports": ",".join(transports) if transports else None,
            })

            return {"success": True, "user": user, "credential_id": credential_id}

        except Exception as e:
            current_app.logger.error(f"Passkey registration failed: {e}")
            return {"success": False, "error": str(e)}

    def authentication_options(self, rp_id=None):
        """
        Generate WebAuthn authentication options for discoverable credentials.

        Returns dict with 'options' (JSON string for browser) and 'challenge' (store for verify).
        """
        rp_id = rp_id or current_app.config.get("PASS0_RP_ID", "localhost")
        challenge = secrets.token_bytes(32)

        options = generate_authentication_options(
            rp_id=rp_id,
            challenge=challenge,
            allow_credentials=[],
            user_verification=UserVerificationRequirement.REQUIRED,
            timeout=60000,
        )

        return {
            "options": options_to_json(options),
            "challenge": bytes_to_base64url(challenge),
        }

    def verify_authentication(self, credential, challenge, rp_id=None, origin=None):
        """
        Verify passkey authentication response.

        Returns dict with 'success', 'user', 'credential_id', or 'error'.
        """
        rp_id = rp_id or current_app.config.get("PASS0_RP_ID", "localhost")
        origin = origin or current_app.config.get("PASS0_ORIGIN", "http://localhost:5000")

        try:
            raw_id = credential.get("rawId")
            if not raw_id:
                return {"success": False, "error": "Missing rawId"}

            credential_id = bytes_to_base64url(base64url_to_bytes(raw_id))
            stored = self.storage.get_passkey_credential_by_id(credential_id)
            if not stored:
                return {"success": False, "error": "Credential not found"}

            verification = verify_authentication_response(
                credential=credential,
                expected_challenge=base64url_to_bytes(challenge),
                expected_rp_id=rp_id,
                expected_origin=origin,
                credential_public_key=base64url_to_bytes(stored["public_key"]),
                credential_current_sign_count=stored["sign_count"],
            )

            self.storage.update_passkey_sign_count(stored["id"], verification.new_sign_count)
            self.storage.update_passkey_last_used(stored["id"])

            user = self.storage.get_user_by_id(stored["user_id"])
            if not user:
                return {"success": False, "error": "User not found"}

            return {"success": True, "user": user, "credential_id": credential_id}

        except Exception as e:
            current_app.logger.error(f"Passkey authentication failed: {e}")
            return {"success": False, "error": str(e)}

    def list_credentials(self, user_id):
        """Get all passkey credentials for a user."""
        return self.storage.get_passkey_credentials(user_id) or []

    def revoke(self, credential_db_id, user_id=None):
        """
        Revoke a passkey credential.

        If user_id provided, verifies ownership first.
        """
        if user_id:
            passkeys = self.storage.get_passkey_credentials(user_id)
            if not any(pk["id"] == credential_db_id for pk in passkeys):
                return {"success": False, "error": "Credential not found"}

        self.storage.revoke_passkey_credential(credential_db_id)
        return {"success": True}