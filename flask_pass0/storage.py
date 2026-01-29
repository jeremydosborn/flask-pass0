from abc import ABC, abstractmethod
from datetime import datetime, timezone
from cryptography.fernet import Fernet
from sqlalchemy import and_
import hashlib
import base64
import json


class StorageAdapter(ABC):
    """Abstract storage interface. Implement for custom backends."""

    # User
    @abstractmethod
    def get_user_by_id(self, user_id):
        pass

    @abstractmethod
    def get_user_by_email(self, email):
        pass

    @abstractmethod
    def create_user(self, email=None):
        pass

    # Magic Link Tokens
    @abstractmethod
    def store_token(self, token, data):
        pass

    @abstractmethod
    def get_token(self, token):
        pass

    # Passkey
    @abstractmethod
    def store_passkey_credential(self, credential_data):
        pass

    @abstractmethod
    def get_passkey_credentials(self, user_id):
        pass

    @abstractmethod
    def get_passkey_credential_by_id(self, credential_id):
        pass

    @abstractmethod
    def update_passkey_sign_count(self, credential_db_id, new_sign_count):
        pass

    @abstractmethod
    def update_passkey_last_used(self, credential_db_id):
        pass

    @abstractmethod
    def revoke_passkey_credential(self, credential_db_id):
        pass

    # TOTP
    @abstractmethod
    def is_2fa_enabled(self, user_id):
        pass

    @abstractmethod
    def get_2fa_secret(self, user_id):
        pass

    @abstractmethod
    def enable_2fa(self, user_id, secret, backup_code_hashes):
        pass

    @abstractmethod
    def disable_2fa(self, user_id):
        pass

    @abstractmethod
    def validate_backup_code(self, user_id, code_hash):
        pass

    @abstractmethod
    def regenerate_backup_codes(self, user_id, code_hashes):
        pass


class SQLAlchemyStorageAdapter(StorageAdapter):
    """SQLAlchemy storage adapter. Works with SQLite, PostgreSQL, MySQL."""

    def __init__(self, user_model, db_session, secret_key):
        from sqlalchemy import Table, Column, Integer, String, Boolean, DateTime, Text, MetaData

        self.session = db_session
        self.user_table = user_model.__table__

        metadata = MetaData()

        self.tokens_table = Table(
            "pass0_tokens", metadata,
            Column("id", Integer, primary_key=True),
            Column("token_hash", String(64), unique=True, nullable=False),
            Column("email", String(255), nullable=False),
            Column("expires_at", DateTime(timezone=True), nullable=False),
            Column("metadata_json", Text),
            Column("created_at", DateTime(timezone=True), nullable=False),
        )

        self.totp_table = Table(
            "pass0_totp", metadata,
            Column("id", Integer, primary_key=True),
            Column("user_id", Integer, nullable=False, unique=True),
            Column("secret_encrypted", Text, nullable=False),
            Column("enabled_at", DateTime(timezone=True), nullable=False),
        )

        self.backup_codes_table = Table(
            "pass0_backup_codes", metadata,
            Column("id", Integer, primary_key=True),
            Column("user_id", Integer, nullable=False),
            Column("code_hash", String(64), nullable=False),
            Column("used", Boolean, default=False),
            Column("created_at", DateTime(timezone=True), nullable=False),
        )

        self.passkeys_table = Table(
            "pass0_passkeys", metadata,
            Column("id", Integer, primary_key=True),
            Column("user_id", Integer, nullable=False),
            Column("credential_id", String(1024), unique=True, nullable=False),
            Column("public_key", Text, nullable=False),
            Column("sign_count", Integer, default=0, nullable=False),
            Column("transports", String(255)),
            Column("created_at", DateTime(timezone=True), nullable=False),
            Column("last_used_at", DateTime(timezone=True)),
            Column("revoked_at", DateTime(timezone=True)),
        )

        key = base64.urlsafe_b64encode(hashlib.sha256(secret_key.encode()).digest())
        self.cipher = Fernet(key)

        metadata.create_all(db_session.get_bind())

    def _hash_token(self, token):
        return hashlib.sha256(token.encode()).hexdigest()

    def _now(self):
        return datetime.now(timezone.utc)

    # User

    def get_user_by_id(self, user_id):
        result = self.session.execute(
            self.user_table.select().where(self.user_table.c.id == user_id)
        ).fetchone()
        return dict(result._mapping) if result else None

    def get_user_by_email(self, email):
        if "email" not in self.user_table.c:
            return None
        result = self.session.execute(
            self.user_table.select().where(self.user_table.c.email == email)
        ).fetchone()
        return dict(result._mapping) if result else None

    def create_user(self, email=None):
        values = {"created_at": self._now()}
        if email and "email" in self.user_table.c:
            values["email"] = email
        result = self.session.execute(
            self.user_table.insert().values(**values).returning(self.user_table)
        )
        self.session.commit()
        return dict(result.fetchone()._mapping)

    # Tokens

    def store_token(self, token, data):
        expires_at = data["expires_at"]
        if isinstance(expires_at, str):
            expires_at = datetime.fromisoformat(expires_at)
        metadata = data.get("metadata")

        self.session.execute(
            self.tokens_table.insert().values(
                token_hash=self._hash_token(token),
                email=data["email"],
                expires_at=expires_at,
                metadata_json=json.dumps(metadata) if metadata else None,
                created_at=self._now(),
            )
        )
        self.session.commit()

    def get_token(self, token):
        token_hash = self._hash_token(token)
        result = self.session.execute(
            self.tokens_table.select().where(self.tokens_table.c.token_hash == token_hash)
        ).fetchone()

        if not result:
            return None

        row = result._mapping
        expires_at = row["expires_at"]
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)

        # Delete token (single-use)
        self.session.execute(
            self.tokens_table.delete().where(self.tokens_table.c.token_hash == token_hash)
        )
        self.session.commit()

        if self._now() > expires_at:
            return None

        data = {"email": row["email"], "expires_at": row["expires_at"].isoformat()}
        if row["metadata_json"]:
            data["metadata"] = json.loads(row["metadata_json"])
        return data

    # Passkey

    def store_passkey_credential(self, data):
        self.session.execute(
            self.passkeys_table.insert().values(
                user_id=data["user_id"],
                credential_id=data["credential_id"],
                public_key=data["public_key"],
                sign_count=data["sign_count"],
                transports=data.get("transports"),
                created_at=self._now(),
            )
        )
        self.session.commit()

    def get_passkey_credentials(self, user_id):
        results = self.session.execute(
            self.passkeys_table.select().where(
                and_(
                    self.passkeys_table.c.user_id == user_id,
                    self.passkeys_table.c.revoked_at == None,
                )
            )
        ).fetchall()
        return [dict(r._mapping) for r in results]

    def get_passkey_credential_by_id(self, credential_id):
        result = self.session.execute(
            self.passkeys_table.select().where(
                and_(
                    self.passkeys_table.c.credential_id == credential_id,
                    self.passkeys_table.c.revoked_at == None,
                )
            )
        ).fetchone()
        return dict(result._mapping) if result else None

    def update_passkey_sign_count(self, credential_db_id, new_sign_count):
        self.session.execute(
            self.passkeys_table.update()
            .where(self.passkeys_table.c.id == credential_db_id)
            .values(sign_count=new_sign_count)
        )
        self.session.commit()

    def update_passkey_last_used(self, credential_db_id):
        self.session.execute(
            self.passkeys_table.update()
            .where(self.passkeys_table.c.id == credential_db_id)
            .values(last_used_at=self._now())
        )
        self.session.commit()

    def revoke_passkey_credential(self, credential_db_id):
        self.session.execute(
            self.passkeys_table.update()
            .where(self.passkeys_table.c.id == credential_db_id)
            .values(revoked_at=self._now())
        )
        self.session.commit()

    # TOTP

    def is_2fa_enabled(self, user_id):
        result = self.session.execute(
            self.totp_table.select().where(self.totp_table.c.user_id == user_id)
        ).fetchone()
        return result is not None

    def get_2fa_secret(self, user_id):
        result = self.session.execute(
            self.totp_table.select().where(self.totp_table.c.user_id == user_id)
        ).fetchone()
        if not result:
            return None
        encrypted = result._mapping["secret_encrypted"]
        if isinstance(encrypted, str):
            encrypted = encrypted.encode()
        return self.cipher.decrypt(encrypted).decode()

    def enable_2fa(self, user_id, secret, backup_code_hashes):
        encrypted = self.cipher.encrypt(secret.encode()).decode()
        self.session.execute(
            self.totp_table.insert().values(
                user_id=user_id,
                secret_encrypted=encrypted,
                enabled_at=self._now(),
            )
        )
        for code_hash in backup_code_hashes:
            self.session.execute(
                self.backup_codes_table.insert().values(
                    user_id=user_id,
                    code_hash=code_hash,
                    used=False,
                    created_at=self._now(),
                )
            )
        self.session.commit()

    def disable_2fa(self, user_id):
        self.session.execute(
            self.totp_table.delete().where(self.totp_table.c.user_id == user_id)
        )
        self.session.execute(
            self.backup_codes_table.delete().where(self.backup_codes_table.c.user_id == user_id)
        )
        self.session.commit()

    def validate_backup_code(self, user_id, code_hash):
        result = self.session.execute(
            self.backup_codes_table.update()
            .where(
                and_(
                    self.backup_codes_table.c.user_id == user_id,
                    self.backup_codes_table.c.code_hash == code_hash,
                    self.backup_codes_table.c.used == False,
                )
            )
            .values(used=True)
            .returning(self.backup_codes_table.c.id)
        )
        self.session.commit()
        return result.fetchone() is not None

    def regenerate_backup_codes(self, user_id, code_hashes):
        self.session.execute(
            self.backup_codes_table.delete().where(self.backup_codes_table.c.user_id == user_id)
        )
        for code_hash in code_hashes:
            self.session.execute(
                self.backup_codes_table.insert().values(
                    user_id=user_id,
                    code_hash=code_hash,
                    used=False,
                    created_at=self._now(),
                )
            )
        self.session.commit()