import base64
import json

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes


def aes_gcm_encrypt(plaintext: str, key: bytes) -> dict:
    cipher = AES.new(key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext.encode("utf-8"))
    return {
        "ciphertext": base64.b64encode(ciphertext).decode(),
        "nonce": base64.b64encode(cipher.nonce).decode(),
        "tag": base64.b64encode(tag).decode(),
    }


def aes_gcm_decrypt(enc_data: dict, key: bytes) -> str:
    return _decrypt_gcm(enc_data, key, validate=False)


def _decrypt_gcm(enc_data: dict, key: bytes, *, validate: bool) -> str:
    nonce = base64.b64decode(enc_data["nonce"], validate=validate)
    ciphertext = base64.b64decode(enc_data["ciphertext"], validate=validate)
    tag = base64.b64decode(enc_data["tag"], validate=validate)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    return cipher.decrypt_and_verify(ciphertext, tag).decode("utf-8")


class SymmetricCrypto:
    """AES-GCM helpers that exchange a Base64-encoded JSON token."""

    @staticmethod
    def generate_key(bits: int = 256) -> bytes:
        if not isinstance(bits, int) or bits not in (128, 192, 256):
            raise ValueError("AES keys must contain 128, 192 or 256 bits")
        return get_random_bytes(bits // 8)

    @staticmethod
    def encrypt(plaintext: str, key: bytes) -> str:
        data = aes_gcm_encrypt(plaintext, key)
        payload = {"ct": data["ciphertext"], "n": data["nonce"], "t": data["tag"]}
        return base64.b64encode(json.dumps(payload).encode("utf-8")).decode("ascii")

    @staticmethod
    def decrypt(token: str, key: bytes) -> str:
        payload = json.loads(base64.b64decode(token, validate=True))
        if not isinstance(payload, dict) or not all(
            isinstance(payload.get(field), str) for field in ("ct", "n", "t")
        ):
            raise ValueError("Invalid AES-GCM token fields")
        data = {"ciphertext": payload["ct"], "nonce": payload["n"], "tag": payload["t"]}
        return _decrypt_gcm(data, key, validate=True)


if __name__ == "__main__":
    key = get_random_bytes(32)
    msg = "Informations confidentielles"
    enc2 = aes_gcm_encrypt(msg, key)

    try:
        print(aes_gcm_decrypt(enc2, get_random_bytes(32)))
    except ValueError as e:
        print("Mauvaise cle:", e)

    try:
        aes_gcm_encrypt(msg, get_random_bytes(10))
    except ValueError as e:
        print("Cle de 10 octets:", e)

    print("nonce =", len(base64.b64decode(enc2["nonce"])), "octets")
    print("tag   =", len(base64.b64decode(enc2["tag"])), "octets")
    '''
    enc = aes_gcm_encrypt(msg, key)
    print(f"Chiffre: {enc}")
    print(f"Dechiffre: {aes_gcm_decrypt(enc, key)}")

    raw = bytearray(base64.b64decode(enc["ciphertext"]))
    raw[0] ^= 0x01
    enc["ciphertext"] = base64.b64encode(bytes(raw)).decode()
    try:
        print(aes_gcm_decrypt(enc, key))
    except ValueError as e:
        print("Attaque detectee:", e)
    '''
