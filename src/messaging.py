"""Hybrid encryption for CryptoVault's local messaging demo."""

import base64
from typing import Dict

from cryptography.hazmat.primitives.asymmetric import rsa

from .asymmetric import generate_rsa_key, rsa_decrypt, rsa_encrypt
from .symmetric import SymmetricCrypto


def encrypt_message(message: str, recipient: rsa.RSAPublicKey) -> Dict[str, str]:
    session_key = SymmetricCrypto.generate_key()
    wrapped_key = rsa_encrypt(session_key.hex(), recipient)
    return {
        "wrapped_key": base64.b64encode(wrapped_key).decode("ascii"),
        "token": SymmetricCrypto.encrypt(message, session_key),
    }


def decrypt_message(envelope: Dict[str, str], recipient: rsa.RSAPrivateKey) -> str:
    wrapped_key = base64.b64decode(envelope["wrapped_key"], validate=True)
    session_key = bytes.fromhex(rsa_decrypt(wrapped_key, recipient))
    return SymmetricCrypto.decrypt(envelope["token"], session_key)


if __name__ == "__main__":
    recipient_key = generate_rsa_key()
    envelope = encrypt_message("Message de démonstration", recipient_key.public_key())
    print(decrypt_message(envelope, recipient_key))
