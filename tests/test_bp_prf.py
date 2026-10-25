import hashlib
import itertools
import unittest

import numpy as np

from ris_sem_project.primitives.bp_prf import BPPRF, encode_input
from ris_sem_project.primitives.gadget import g_inverse
from ris_sem_project.primitives.ring import Ring

Q = 2**28 - 57
N = 8
ELL = 28
L = 6
RING = Ring(Q, N)
RNG = np.random.default_rng(6)


def negacyclic(a, b):
    """a * b in Z_q[X]/(X^n + 1) on lists of Python integers."""
    c = [0] * N
    for i, x in enumerate(a):
        for j, y in enumerate(b):
            if i + j < N:
                c[i + j] += x * y
            else:
                c[i + j - N] -= x * y
    return [v % Q for v in c]


def reference_a_x(a0, a1, x):
    """a_x from Lemma 1: v = a_{x_L}, then v_j = sum_k a_{x_i, k} * G^{-1}(v)[k][j]."""
    a = (a0.tolist(), a1.tolist())
    v = a[x[-1]]
    for bit in reversed(x[:-1]):
        new_v = []
        for j in range(ELL):
            total = [0] * N
            for k in range(ELL):
                bit_k_of_v_j = [(c >> k) & 1 for c in v[j]]
                total = [s + p for s, p in zip(total, negacyclic(a[bit][k], bit_k_of_v_j))]
            new_v.append([s % Q for s in total])
        v = new_v
    return v


class GadgetTest(unittest.TestCase):
    def test_g_inverse_is_binary_and_recomposes(self):
        v = RNG.integers(0, Q, (ELL, N))
        decomposition = g_inverse(RING, v)
        self.assertEqual(decomposition.shape, (ELL, ELL, N))
        self.assertTrue(np.isin(decomposition, (0, 1)).all())
        recomposed = [
            [sum(int(decomposition[k, j, c]) << k for k in range(ELL)) for c in range(N)] for j in range(ELL)
        ]
        self.assertEqual(recomposed, v.tolist())


class BPPRFTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.a0, cls.a1 = RNG.integers(0, Q, (ELL, N)), RNG.integers(0, Q, (ELL, N))
        cls.bp = BPPRF(RING, cls.a0, cls.a1, L)
        cls.inputs = [[0] * L, [1] * L, [1, 0, 1, 0, 1, 0], [0, 0, 1, 1, 0, 1], [1, 1, 0, 1, 0, 0]]

    def test_a_x_matches_definition(self):
        for x in self.inputs:
            with self.subTest(x=x):
                actual = self.bp.a_x(np.array(x, dtype=np.uint8))
                self.assertEqual(actual.tolist(), reference_a_x(self.a0, self.a1, x))

    def test_evaluate_rounds_a_x_times_k_to_bits(self):
        k = RNG.integers(0, Q, N)
        x = self.inputs[2]
        product = [negacyclic(row, k.tolist()) for row in reference_a_x(self.a0, self.a1, x)]
        expected = [((2 * y + Q // 2) // Q) % 2 for row in product for y in row]
        self.assertEqual(self.bp.evaluate(k, np.array(x, dtype=np.uint8)).tolist(), expected)

    def test_evaluate_is_deterministic_and_separates_all_inputs(self):
        k = RNG.integers(0, Q, N)
        x = np.array(self.inputs[3], dtype=np.uint8)
        self.assertEqual(self.bp.evaluate(k, x).tolist(), self.bp.evaluate(k, x).tolist())
        outputs = {self.bp.evaluate(k, np.array(x, dtype=np.uint8)).tobytes() for x in itertools.product((0, 1), repeat=L)}
        self.assertEqual(len(outputs), 2**L)

    def test_encode_input_takes_leading_sha3_bits(self):
        data = b"QPASE/test/encode"
        digest = int.from_bytes(hashlib.sha3_256(data).digest(), "big")
        for length in (1, L, 128, 256):
            with self.subTest(L=length):
                expected = [(digest >> (255 - i)) & 1 for i in range(length)]
                self.assertEqual(encode_input(data, length).tolist(), expected)


if __name__ == "__main__":
    unittest.main()
