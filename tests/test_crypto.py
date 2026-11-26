import base64
import json
import unittest

from src.hashing import SecureHash
from src.symmetric import SymmetricCrypto


class HashingTests(unittest.TestCase):
    def test_sha256_known_digest(self):
        self.assertEqual(
            SecureHash.sha256("abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        )

    def test_bcrypt_accepts_only_the_correct_password(self):
        password = "Mot de passe synthétique"
        hashed = SecureHash.hash_password(password)
        self.assertTrue(SecureHash.verify_password(password, hashed))
        self.assertFalse(SecureHash.verify_password("autre", hashed))

    def test_bcrypt_rejects_a_password_over_the_utf8_byte_limit(self):
        password = "é" * 37
        with self.assertRaises(ValueError):
            SecureHash.hash_password(password)
        self.assertFalse(SecureHash.verify_password(password, "invalid-hash"))

    def test_hmac_sha256_known_digest(self):
        self.assertEqual(
            SecureHash.hmac_sha256("Hi There", b"\x0b" * 20),
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7",
        )


class SymmetricCryptoTests(unittest.TestCase):
    def test_round_trip_with_supported_key_sizes(self):
        plaintext = "Message synthétique"
        for bits in (128, 192, 256):
            with self.subTest(bits=bits):
                key = SymmetricCrypto.generate_key(bits)
                token = SymmetricCrypto.encrypt(plaintext, key)
                self.assertEqual(SymmetricCrypto.decrypt(token, key), plaintext)

    def test_rejects_the_wrong_key(self):
        token = SymmetricCrypto.encrypt("Message synthétique", b"\x01" * 32)
        with self.assertRaises(ValueError):
            SymmetricCrypto.decrypt(token, b"\x02" * 32)

    def test_rejects_a_modified_authentication_tag(self):
        key = SymmetricCrypto.generate_key()
        token = SymmetricCrypto.encrypt("Message synthétique", key)
        payload = json.loads(base64.b64decode(token))
        tag = bytearray(base64.b64decode(payload["t"]))
        tag[0] ^= 1
        payload["t"] = base64.b64encode(tag).decode("ascii")
        encoded = json.dumps(payload).encode("utf-8")
        altered_token = base64.b64encode(encoded).decode("ascii")
        with self.assertRaises(ValueError):
            SymmetricCrypto.decrypt(altered_token, key)
