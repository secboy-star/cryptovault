from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import base64


def aes_gcm_encrypt(plaintext: str, key: bytes) -> dict:
    cipher = AES.new(key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext.encode("utf-8"))
    return {
        "ciphertext": base64.b64encode(ciphertext).decode(),
        "nonce": base64.b64encode(cipher.nonce).decode(),
        "tag": base64.b64encode(tag).decode(),
    }


def aes_gcm_decrypt(enc_data: dict, key: bytes) -> str:
    cipher = AES.new(key, AES.MODE_GCM,
                     nonce=base64.b64decode(enc_data["nonce"]))
    return cipher.decrypt_and_verify(
        base64.b64decode(enc_data["ciphertext"]),
        base64.b64decode(enc_data["tag"])).decode("utf-8")


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