import unittest

from ris_sem_project.primitives import signature


class SignatureTest(unittest.TestCase):
    def setUp(self):
        self.pk, self.sk = signature.keypair_from_seed(bytes(range(32)))
        self.msg = b"outsource item 7"
        self.sig = signature.sign(self.sk, self.msg)

    def test_same_seed_same_keys(self):
        self.assertEqual(signature.keypair_from_seed(bytes(range(32))), (self.pk, self.sk))

    def test_different_seed_different_pk(self):
        pk2, _ = signature.keypair_from_seed(bytes(32))
        self.assertNotEqual(pk2, self.pk)

    def test_bad_seed_length(self):
        for n in (0, 31, 33):
            with self.assertRaises(ValueError):
                signature.keypair_from_seed(bytes(n))

    def test_round_trip(self):
        self.assertTrue(signature.verify(self.pk, self.msg, self.sig))

    def test_modified_message(self):
        self.assertFalse(signature.verify(self.pk, self.msg + b"x", self.sig))

    def test_modified_signature(self):
        bad = bytearray(self.sig)
        bad[10] ^= 1
        self.assertFalse(signature.verify(self.pk, self.msg, bytes(bad)))

    def test_truncated_signature(self):
        self.assertFalse(signature.verify(self.pk, self.msg, self.sig[:-1]))
        self.assertFalse(signature.verify(self.pk, self.msg, b""))

    def test_different_key(self):
        pk2, _ = signature.keypair_from_seed(bytes(32))
        self.assertFalse(signature.verify(pk2, self.msg, self.sig))

    def test_malformed_key_does_not_raise(self):
        self.assertFalse(signature.verify(b"", self.msg, self.sig))
        self.assertFalse(signature.verify(self.pk[:-1], self.msg, self.sig))


if __name__ == "__main__":
    unittest.main()
