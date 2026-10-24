import unittest

import numpy as np

from ris_sem_project.primitives.bp_prf import BPPRF
from ris_sem_project.primitives.hkdf import Hkdf
from ris_sem_project.primitives.prf import key_to_ring, prf
from ris_sem_project.primitives.ring import Ring

Q = 2**28 - 57
RING = Ring(Q, 16)
KEY_BYTES = 28 * 16 // 8
RNG = np.random.default_rng(10)


def random_key():
    return RNG.bytes(KEY_BYTES)


class KeyToRingTest(unittest.TestCase):
    def test_reads_big_endian_ell_bit_groups_mod_q(self):
        key = ((5 << 28) | (Q + 3)).to_bytes(7, "big")
        self.assertEqual(key_to_ring(Ring(Q, 2), key).tolist(), [5, 3])

    def test_rejects_a_key_of_the_wrong_length(self):
        for size in (0, KEY_BYTES - 1, KEY_BYTES + 1):
            with self.subTest(size=size), self.assertRaises(ValueError):
                key_to_ring(RING, bytes(size))


class PrfHkdfTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.bp = BPPRF(RING, RNG.integers(0, Q, (28, 16)), RNG.integers(0, Q, (28, 16)), 128)

    def test_prf_is_a_deterministic_keyed_function(self):
        key = random_key()
        v = prf(self.bp, key, b"rho")
        self.assertEqual(len(v), KEY_BYTES)
        self.assertEqual(prf(self.bp, key, b"rho"), v)
        self.assertNotEqual(prf(self.bp, key, b"rho'"), v)
        self.assertNotEqual(prf(self.bp, random_key(), b"rho"), v)

    def test_hkdf_is_deterministic_and_separates_info_ikm_and_salt(self):
        ikm = random_key()
        dsk = Hkdf(self.bp, ikm).derive(b"w")
        self.assertEqual(len(dsk), KEY_BYTES)
        self.assertEqual(Hkdf(self.bp, ikm).derive(b"w"), dsk)
        self.assertNotEqual(Hkdf(self.bp, ikm).derive(b"w'"), dsk)
        self.assertNotEqual(Hkdf(self.bp, random_key()).derive(b"w"), dsk)
        self.assertNotEqual(Hkdf(self.bp, ikm, salt=b"other salt").derive(b"w"), dsk)

    def test_hkdf_output_keys_the_prf(self):
        dsk = Hkdf(self.bp, random_key()).derive(b"w")
        self.assertEqual(len(prf(self.bp, dsk, b"rho")), KEY_BYTES)


if __name__ == "__main__":
    unittest.main()
