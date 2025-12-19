"""
passkey.py — minimal passkey (WebAuthn) module for flask-pass0

Design goals:
- Additive: does not change existing magic-link/2FA/device-binding behavior.
- Lightweight: no UI, no email, no CSRF/rate limiting, no sessions.
- Safe-by-default: server-generated challenge, short-lived, single-use.
- Verification delegated to the storage adapter (or a later optional dependency).

Expected storage adapter methods (to be implemented in storage.py):
- create_passkey_challenge(challenge: str, email: str|None, expires_at: datetime, purpose: str) -> str
- consume_passkey_challenge(challenge_id: str) -> dict|None
- verify_passkey_assertion(challenge_row: dict, assertion: dict) -> tuple[bool, dict|None]
"""

from __future__ import annotations

import base64
import os
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional, Tuple


@dataclass(frozen=True)
class PasskeyBeginResult:
    challenge_id: str
    publicKey: Dict[str, Any]


class PasskeyAuth:
    """
    Minimal passkey login helper.

    Typical flow:
      1) begin_login(email?) -> {challenge_id, publicKey:{...}}
      2) browser: navigator.credentials.get({publicKey})
      3) finish_login(challenge_id, assertion) -> (ok, user, err)
      4) auth.py establishes session + runs existing _check_device_and_2fa(user)
    """

    def __init__(
        self,
        storage,
        *,
        rp_id: str,
        origin: Optional[str] = None,
        challenge_ttl_seconds: int = 120,
        timeout_ms: int = 60000,
        user_verification: str = "preferred",  # "required" | "preferred" | "discouraged"
    ):
        self.storage = storage
        self.rp_id = rp_id
        self.origin = origin
        self.challenge_ttl_seconds = int(challenge_ttl_seconds)
        self.timeout_ms = int(timeout_ms)
        self.user_verification = user_verification

    @staticmethod
    def _b64url_no_pad(raw: bytes) -> str:
        return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")

    def begin_login(self, *, email: Optional[str] = None) -> Dict[str, Any]:
        """
        Create and store a one-time challenge (single-use, short-lived).

        Returns a dict shaped for typical JS usage:
          {
            "challenge_id": "...",
            "publicKey": { ...WebAuthn options... }
          }
        """
        # Server-side random challenge (must be verified server-side on finish)
        challenge = self._b64url_no_pad(os.urandom(32))
        expires_at = datetime.now(timezone.utc) + timedelta(seconds=self.challenge_ttl_seconds)

        # Persist challenge (single-use)
        challenge_id = self.storage.create_passkey_challenge(
            challenge=challenge,
            email=email,
            expires_at=expires_at,
            purpose="login",
        )

        # NOTE: In a full implementation you would also set allowCredentials
        # if using identifier-first (email) login, based on stored credential IDs.
        public_key = {
            "challenge": challenge,
            "rpId": self.rp_id,
            "timeout": self.timeout_ms,
            "userVerification": self.user_verification,
            # "allowCredentials": [{"type": "public-key", "id": "<base64url>"}],
        }

        return {"challenge_id": challenge_id, "publicKey": public_key}

    def finish_login(self, challenge_id: str, assertion: Dict[str, Any]) -> Tuple[bool, Optional[Dict[str, Any]], str]:
        """
        Consume the stored challenge (single-use) and verify the assertion.

        Returns:
          (True, user_dict, "")
          (False, None, "reason")
        """
        if not challenge_id:
            return False, None, "Missing challenge_id"
        if not assertion:
            return False, None, "Missing assertion"

        # Consume challenge atomically (prevents replay)
        row = self.storage.consume_passkey_challenge(challenge_id)
        if not row:
            return False, None, "Invalid or expired challenge"

        verifier = getattr(self.storage, "verify_passkey_assertion", None)
        if not callable(verifier):
            return False, None, "Passkey verification not configured"

        ok, user = verifier(row, assertion)
        if not ok or not user:
            return False, None, "Passkey verification failed"

        return True, user, ""