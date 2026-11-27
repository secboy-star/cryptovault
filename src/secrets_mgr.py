import json
from hashlib import pbkdf2_hmac
from os import fsync
from pathlib import Path
from secrets import token_bytes
from tempfile import NamedTemporaryFile

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


def save_vault(path: Path, payload: str, password: str) -> None:
    """Replace a local vault file once the encrypted snapshot has been written."""
    path = Path(path)
    sealed = seal_vault(payload, password)
    temporary = NamedTemporaryFile(mode="w", encoding="utf-8", dir=path.parent, delete=False)
    temporary_path = Path(temporary.name)
    try:
        with temporary:
            temporary.write(sealed)
            temporary.flush()
            fsync(temporary.fileno())
        temporary_path.replace(path)
    finally:
        temporary_path.unlink(missing_ok=True)


def load_vault(path: Path, password: str) -> str:
    return open_vault(Path(path).read_text(encoding="utf-8"), password)
