import json
from hashlib import pbkdf2_hmac
from secrets import token_bytes

from .symmetric import SymmetricCrypto


def _vault_key(password: str, salt: bytes) -> bytes:
    if not password:
        raise ValueError("A vault password is required")
    return pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 600_000, dklen=32)


def seal_vault(payload: str, password: str) -> str:
    salt = token_bytes(16)
    token = SymmetricCrypto.encrypt(payload, _vault_key(password, salt))
    return json.dumps({"version": 1, "salt": salt.hex(), "token": token})


def open_vault(sealed: str, password: str) -> str:
    envelope = json.loads(sealed)
    version = envelope.get("version") if isinstance(envelope, dict) else None
    if type(version) is not int or version != 1:
        raise ValueError("Unsupported vault format")
    if not all(isinstance(envelope.get(field), str) for field in ("salt", "token")):
        raise ValueError("Invalid vault envelope")
    salt = bytes.fromhex(envelope["salt"])
    if len(salt) != 16:
        raise ValueError("Invalid vault salt")
    return SymmetricCrypto.decrypt(envelope["token"], _vault_key(password, salt))
