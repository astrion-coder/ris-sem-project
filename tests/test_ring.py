import math
import unittest

import numpy as np

from ris_sem_project.primitives.ring import Ring
from ris_sem_project.primitives.sampling import gaussian, uniform, uniform_zq

Q = 2**28 - 57
RNG = np.random.default_rng(20241024)


def schoolbook(a, b, q):
    """a * b in Z_q[X]/(X^n + 1) with Python integers: X^n wraps to -1."""
    n = len(a)
    full = np.zeros(2 * n, dtype=object)
    b = np.array([int(c) for c in b], dtype=object)
    for i in range(n):
        full[i : i + n] += int(a[i]) * b
    return (full[:n] - full[n:]) % q


class MulTest(unittest.TestCase):
    def assert_matches_schoolbook(self, ring, a, b):
        self.assertEqual(ring.mul(a, b).tolist(), schoolbook(a, b, ring.q).tolist())

    def test_uniform_operands(self):
        for n in (512, 595):
            ring = Ring(Q, n)
            for _ in range(3):
                with self.subTest(n=n):
                    self.assert_matches_schoolbook(ring, RNG.integers(0, Q, n), RNG.integers(0, Q, n))

    def test_uniform_times_small(self):
        for n in (512, 595):
            ring = Ring(Q, n)
            small = ring.small(RNG.integers(-39, 40, n))
            with self.subTest(n=n):
                self.assert_matches_schoolbook(ring, RNG.integers(0, Q, n), small)
                self.assert_matches_schoolbook(ring, small, RNG.integers(0, Q, n))

    def test_largest_coefficients(self):
        ring = Ring(Q, 595)
        top = np.full(595, Q - 1)
        self.assert_matches_schoolbook(ring, top, top)

    def test_vector_times_element_broadcasts(self):
        ring = Ring(Q, 16)
        vector, element = RNG.integers(0, Q, (4, 16)), RNG.integers(0, Q, 16)
        expected = [schoolbook(row, element, Q).tolist() for row in vector]
        self.assertEqual(ring.mul(vector, element).tolist(), expected)


class ArithmeticTest(unittest.TestCase):
    ring = Ring(Q, 8)

    def test_add_sub_neg_reduce_mod_q(self):
        a = [0, 1, Q - 1, Q - 2, 5, 123456789, Q // 2, Q // 2 + 1]
        b = [0, Q - 1, Q - 1, 3, 7, 200000000, Q // 2, Q // 2]
        x, y = np.array(a), np.array(b)
        self.assertEqual(self.ring.add(x, y).tolist(), [(u + v) % Q for u, v in zip(a, b)])
        self.assertEqual(self.ring.sub(x, y).tolist(), [(u - v) % Q for u, v in zip(a, b)])
        self.assertEqual(self.ring.neg(x).tolist(), [-u % Q for u in a])

    def test_small_and_centered_representatives(self):
        h = (Q - 1) // 2
        self.assertEqual(self.ring.small([-1, 0, 5, -Q]).tolist(), [Q - 1, 0, 5, 0])
        self.assertEqual(self.ring.centered(np.array([0, 1, h, h + 1, Q - 1])).tolist(), [0, 1, h, -h, -1])

    def test_ell_is_ceil_log2_q(self):
        self.assertEqual(Ring(Q, 8).ell, 28)
        self.assertEqual(Ring(9, 8).ell, 4)
        self.assertEqual(Ring(7, 8).ell, 3)

    def test_rejects_unsupported_moduli_and_degree(self):
        for q, n in ((Q + 1, 8), (2**28 + 1, 8), (1, 8), (Q, 0)):
            with self.subTest(q=q, n=n), self.assertRaises(ValueError):
                Ring(q, n)


class SerializationTest(unittest.TestCase):
    def test_to_bytes_is_little_endian_uint32(self):
        ring = Ring(Q, 2)
        expected = (1).to_bytes(4, "little") + (Q - 1).to_bytes(4, "little")
        self.assertEqual(ring.to_bytes(np.array([1, Q - 1])), expected)

    def test_from_bytes_round_trips_and_rejects_malformed(self):
        ring = Ring(Q, 4)
        a = RNG.integers(0, Q, (3, 4))
        data = ring.to_bytes(a)
        self.assertEqual(ring.from_bytes(data, (3, 4)).tolist(), a.tolist())
        for bad in (data[:-1], data + b"\0", Q.to_bytes(4, "little") + data[4:]):
            with self.subTest(size=len(bad)), self.assertRaises(ValueError):
                ring.from_bytes(bad, (3, 4))

    def test_bits_round_trip_and_reject_malformed(self):
        ring = Ring(Q, 595)
        bits = RNG.integers(0, 2, (ring.ell, ring.n), dtype=np.uint8)
        data = ring.pack_bits(bits)
        self.assertEqual(len(data), math.ceil(28 * 595 / 8))
        self.assertEqual(ring.unpack_bits(data).tolist(), bits.tolist())
        self.assertEqual(ring.pack_bits(bits.reshape(-1)), data)
        for bad in (data[:-1], data + b"\0", data[:-1] + bytes([data[-1] | 1])):
            with self.subTest(size=len(bad)), self.assertRaises(ValueError):
                ring.unpack_bits(bad)


class SamplingTest(unittest.TestCase):
    ring = Ring(Q, 8)

    def test_uniform_covers_zq_evenly(self):
        x = uniform(self.ring, (200, 1000))
        self.assertEqual(x.shape, (200, 1000))
        self.assertTrue(((x >= 0) & (x < Q)).all())
        self.assertAlmostEqual(np.mean(x >= Q // 2), 0.5, delta=0.01)
        self.assertAlmostEqual(np.mean(x % 2), 0.5, delta=0.01)

    def test_gaussian_follows_chi_sigma(self):
        sigma = 3.2
        tail = math.ceil(12 * sigma)
        rho = {m: math.exp(-m * m / (2 * sigma**2)) for m in range(-tail, tail + 1)}
        total = sum(rho.values())
        std = math.sqrt(sum(m * m * w for m, w in rho.items()) / total)
        x = self.ring.centered(gaussian(self.ring, (400, 500), sigma))
        self.assertEqual(x.shape, (400, 500))
        self.assertLessEqual(np.abs(x).max(), tail)
        self.assertAlmostEqual(x.mean(), 0, delta=0.05)
        self.assertAlmostEqual(x.std(), std, delta=0.05)
        self.assertAlmostEqual(np.mean(x == 0), rho[0] / total, delta=0.005)
        self.assertAlmostEqual(np.mean(x == 1), rho[1] / total, delta=0.005)

    def test_uniform_zq_hits_every_residue(self):
        self.assertEqual({uniform_zq(7) for _ in range(500)}, set(range(7)))


if __name__ == "__main__":
    unittest.main()
