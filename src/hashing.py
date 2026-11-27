"""Hash, password and token helpers for CryptoVault."""

import hashlib
import hmac
import secrets

import bcrypt


class SecureHash:
    @staticmethod
    def sha256(data: str) -> str:
        return hashlib.sha256(data.encode("utf-8")).hexdigest()

    @staticmethod
    def hash_password(password: str) -> str:
        encoded = password.encode("utf-8")
        if len(encoded) > 72:
            raise ValueError("bcrypt passwords must fit in 72 UTF-8 bytes")
        return bcrypt.hashpw(encoded, bcrypt.gensalt(rounds=12)).decode("ascii")

    @staticmethod
    def verify_password(password: str, hashed: str) -> bool:
        encoded = password.encode("utf-8")
        if len(encoded) > 72:
            return False
        try:
            return bcrypt.checkpw(encoded, hashed.encode("ascii"))
        except ValueError:
            return False

    @staticmethod
    def hmac_sha256(message: str, key: bytes) -> str:
        return hmac.new(key, message.encode("utf-8"), hashlib.sha256).hexdigest()

    @staticmethod
    def verify_hmac_sha256(message: str, key: bytes, digest: str) -> bool:
        if not isinstance(digest, str) or len(digest) != 64:
            return False
        try:
            supplied = bytes.fromhex(digest)
        except ValueError:
            return False
        expected = bytes.fromhex(SecureHash.hmac_sha256(message, key))
        return len(supplied) == len(expected) and hmac.compare_digest(expected, supplied)

    @staticmethod
    def generate_token(length: int = 32) -> str:
        return secrets.token_hex(length)
