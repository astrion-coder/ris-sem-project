import hashlib
import unittest

import numpy as np

from ris_sem_project.primitives import linear_hash
from ris_sem_project.primitives.linear_hash import linear_hash as H
from ris_sem_project.primitives.ring import Ring
from ris_sem_project.primitives.sampling import uniform

Q = 2**28 - 57
RING = Ring(Q, 512)


def matrix_of(ring):
    """A_H read through H alone: H(e_c) is column c, and a unit vector overflows nothing."""
    return H(ring, np.eye(ring.n, dtype=np.int64)).T


def masked_words(q, count):
    """The first count 4-byte little-endian words of SHAKE256(b"QPASE/H"), masked to ell bits."""
    mask = (1 << (q - 1).bit_length()) - 1
    raw = hashlib.shake_256(b"QPASE/H").digest(4 * count)
    return [int.from_bytes(raw[i : i + 4], "little") & mask for i in range(0, len(raw), 4)]


def reference_matrix(q, n, words):
    """A_H by its definition: the first n * n masked words below q, row-major."""
    accepted = [w for w in masked_words(q, words) if w < q]
    assert len(accepted) >= n * n
    return [accepted[r * n : (r + 1) * n] for r in range(n)]


def big_int_product(matrix, x, q):
    return [sum(int(a) * int(c) for a, c in zip(row, x)) % q for row in matrix]


class LinearityTest(unittest.TestCase):
    def test_additive(self):
        for ring in (RING, Ring(Q, 16)):
            with self.subTest(n=ring.n):
                a, b = uniform(ring, (ring.n,)), uniform(ring, (ring.n,))
                np.testing.assert_array_equal(H(ring, (a + b) % Q), (H(ring, a) + H(ring, b)) % Q)

    def test_homogeneous_for_integer_scalars(self):
        a = uniform(RING, (RING.n,))
        for c in (0, 1, 7, Q - 1, Q, -3, 2**40 + 5):
            with self.subTest(c=c):
                expected = (c * H(RING, a).astype(object) % Q).astype(np.int64)
                np.testing.assert_array_equal(H(RING, a * (c % Q) % Q), expected)

    def test_commitment_identity_of_key_update(self):
        ring = Ring(Q, 16)
        alphas = [uniform(ring, (ring.n,)) for _ in range(3)]
        for i in (1, 2, 5):
            share = sum(pow(i, k, Q) * alpha for k, alpha in enumerate(alphas, start=1)) % Q
            committed = sum(pow(i, k, Q) * H(ring, alpha) for k, alpha in enumerate(alphas, start=1)) % Q
            np.testing.assert_array_equal(H(ring, share), committed)

    def test_zero_hashes_to_zero_and_batches_agree_with_rows(self):
        self.assertFalse(H(RING, np.zeros(RING.n, dtype=np.int64)).any())
        batch = uniform(RING, (3, RING.n))
        np.testing.assert_array_equal(H(RING, batch), np.stack([H(RING, row) for row in batch]))

    def test_wrong_length_is_refused(self):
        with self.assertRaises(ValueError):
            H(RING, np.zeros(RING.n - 1, dtype=np.int64))


class PublicMatrixTest(unittest.TestCase):
    def test_matrix_is_the_shake256_expansion_at_param_I(self):
        ring = RING
        expected = np.array(reference_matrix(Q, ring.n, 2 * ring.n**2), dtype=np.int64)
        np.testing.assert_array_equal(matrix_of(ring), expected)

    def test_rejection_sampling_skips_words_at_or_above_q(self):
        ring = Ring(2**27 + 1, 8)
        words = 8 * ring.n**2
        accepted = 0
        for consumed, word in enumerate(masked_words(ring.q, words), start=1):
            accepted += word < ring.q
            if accepted == ring.n**2:
                break
        self.assertGreater(consumed, ring.n**2, "this q must actually trigger a rejection")
        reference = np.array(reference_matrix(ring.q, ring.n, words), dtype=np.int64)
        np.testing.assert_array_equal(matrix_of(ring), reference)

    def test_matrix_is_a_pure_function_of_q_and_n(self):
        ring = Ring(Q, 64)
        first = matrix_of(ring)
        linear_hash._matrix.cache_clear()
        np.testing.assert_array_equal(matrix_of(ring), first)
        self.assertTrue(((0 <= first) & (first < Q)).all())
        self.assertGreater(len(np.unique(first)), ring.n * ring.n // 2)


class ExactnessTest(unittest.TestCase):
    def test_product_equals_python_big_ints_at_n_512(self):
        matrix = matrix_of(RING).tolist()
        inputs = {
            "all q-1": np.full(RING.n, Q - 1, dtype=np.int64),
            "uniform 1": uniform(RING, (RING.n,)),
            "uniform 2": uniform(RING, (RING.n,)),
            "limb edges": np.where(np.arange(RING.n) % 2 == 0, 2**14 - 1, 2**14).astype(np.int64),
        }
        for name, x in inputs.items():
            with self.subTest(name):
                self.assertEqual(H(RING, x).tolist(), big_int_product(matrix, x, Q))


if __name__ == "__main__":
    unittest.main()
