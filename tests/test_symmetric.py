import unittest

from ris_sem_project.primitives import symmetric


class SymmetricTest(unittest.TestCase):
    def setUp(self):
        self.key = bytes(range(32))
        self.pt = b"item payload"

    def test_round_trip(self):
        self.assertEqual(symmetric.decrypt(self.key, symmetric.encrypt(self.key, self.pt)), self.pt)

    def test_empty_plaintext(self):
        self.assertEqual(symmetric.decrypt(self.key, symmetric.encrypt(self.key, b"")), b"")

    def test_wrong_key(self):
        self.assertIsNone(symmetric.decrypt(bytes(32), symmetric.encrypt(self.key, self.pt)))

    def test_flipped_byte_anywhere(self):
        blob = symmetric.encrypt(self.key, self.pt)
        for i in range(len(blob)):
            bad = bytearray(blob)
            bad[i] ^= 1
            self.assertIsNone(symmetric.decrypt(self.key, bytes(bad)), i)

    def test_truncated_blob(self):
        blob = symmetric.encrypt(self.key, self.pt)
        for n in (0, 1, 27, len(blob) - 1):
            self.assertIsNone(symmetric.decrypt(self.key, blob[:n]), n)

    def test_encryptions_differ(self):
        self.assertNotEqual(symmetric.encrypt(self.key, self.pt), symmetric.encrypt(self.key, self.pt))

    def test_blob_layout(self):
        self.assertEqual(len(symmetric.encrypt(self.key, self.pt)), 12 + len(self.pt) + 16)

    def test_encrypt_rejects_bad_key_length(self):
        with self.assertRaises(ValueError):
            symmetric.encrypt(bytes(16), self.pt)

    def test_decrypt_bad_key_length_is_none(self):
        self.assertIsNone(symmetric.decrypt(bytes(16), symmetric.encrypt(self.key, self.pt)))

    def test_aes_key(self):
        material = bytes(range(64))
        self.assertEqual(symmetric.aes_key(material), material[:32])
        self.assertEqual(symmetric.aes_key(material[:32]), material[:32])
        with self.assertRaises(ValueError):
            symmetric.aes_key(material[:31])


if __name__ == "__main__":
    unittest.main()
