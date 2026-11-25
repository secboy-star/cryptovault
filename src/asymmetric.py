"""RSA encryption and signatures for CryptoVault exercises."""

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa


def generate_rsa_key() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def rsa_encrypt(message: str, public_key: rsa.RSAPublicKey) -> bytes:
    return public_key.encrypt(message.encode("utf-8"), _oaep())


def rsa_decrypt(ciphertext: bytes, private_key: rsa.RSAPrivateKey) -> str:
    return private_key.decrypt(ciphertext, _oaep()).decode("utf-8")


def rsa_sign(message: str, private_key: rsa.RSAPrivateKey) -> bytes:
    return private_key.sign(
        message.encode("utf-8"), padding.PKCS1v15(), hashes.SHA256()
    )


def rsa_verify(message: str, signature: bytes, public_key: rsa.RSAPublicKey) -> bool:
    try:
        public_key.verify(
            signature, message.encode("utf-8"), padding.PKCS1v15(), hashes.SHA256()
        )
    except InvalidSignature:
        return False
    return True


def _oaep() -> padding.OAEP:
    return padding.OAEP(
        mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None
    )
