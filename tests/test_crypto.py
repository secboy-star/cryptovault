import unittest

from src.hashing import SecureHash


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
