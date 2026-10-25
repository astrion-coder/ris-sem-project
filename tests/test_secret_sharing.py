import itertools
import math
import unittest

from ris_sem_project.primitives.ring import Ring
from ris_sem_project.primitives.secret_sharing import (
    NonIntegerLagrangeError,
    genkey,
    genshare,
    lagrange_at_zero,
    reconstruct,
)

Q = 2**28 - 57
RING = Ring(Q, 16)
SIGMA = 3.2
TAIL = math.ceil(12 * SIGMA)

INTEGER_SUBSETS = {(3, 2): [(1, 2), (2, 3)], (4, 3): [(1, 2, 3), (1, 3, 4), (2, 3, 4)]}
NON_INTEGER_SUBSETS = {(3, 2): [(1, 3)], (4, 3): [(1, 2, 4)]}


def interpolate_at_zero(points):
    """f(0) over Z_q from {x: f(x)} by Lagrange interpolation with modular inverses."""
    value = [0] * RING.n
    for i, y in points.items():
        numerator = math.prod(j for j in points if j != i)
        denominator = math.prod(j - i for j in points if j != i)
        lam = numerator * pow(denominator, -1, Q)
        value = [(v + lam * int(c)) % Q for v, c in zip(value, y)]
    return value


def centered(values):
    return [v - Q if v > Q // 2 else v for v in values]


def deal(N, t):
    """The DKG: every S_i runs Genshare, every S_j runs Genkey. Returns (dealt shares, keys)."""
    ids = range(1, N + 1)
    dealt = [genshare(RING, t, ids, SIGMA) for _ in ids]
    keys = {j: genkey(RING, [shares[j] for shares in dealt]) for j in ids}
    return dealt, keys


def secret_of(shares, t):
    return interpolate_at_zero({j: shares[j] for j in range(1, t + 1)})


class LagrangeTest(unittest.TestCase):
    def test_examples(self):
        self.assertEqual(lagrange_at_zero([1, 2]), {1: 2, 2: -1})
        self.assertEqual(lagrange_at_zero([2, 3]), {2: 3, 3: -2})
        with self.assertRaises(NonIntegerLagrangeError):
            lagrange_at_zero([1, 3])
        self.assertTrue(issubclass(NonIntegerLagrangeError, ValueError))

    def test_first_t_servers_have_binomial_coefficients(self):
        for t in range(1, 7):
            expected = {i: (-1) ** (i + 1) * math.comb(t, i) for i in range(1, t + 1)}
            self.assertEqual(lagrange_at_zero(range(1, t + 1)), expected)


class DKGTest(unittest.TestCase):
    def test_any_t_shares_of_one_dealer_give_the_same_secret(self):
        for N, t in INTEGER_SUBSETS:
            dealt, _ = deal(N, t)
            for shares in dealt:
                with self.subTest(N=N, t=t):
                    values = {
                        tuple(interpolate_at_zero({j: shares[j] for j in subset}))
                        for subset in itertools.combinations(range(1, N + 1), t)
                    }
                    self.assertEqual(len(values), 1)

    def test_every_integer_subset_reconstructs_the_sum_of_secrets(self):
        for (N, t), subsets in INTEGER_SUBSETS.items():
            dealt, keys = deal(N, t)
            master = [sum(column) % Q for column in zip(*(secret_of(shares, t) for shares in dealt))]
            for subset in subsets:
                with self.subTest(N=N, t=t, subset=subset):
                    self.assertEqual(reconstruct(RING, {j: keys[j] for j in subset}).tolist(), master)
            for subset in NON_INTEGER_SUBSETS[(N, t)]:
                with self.subTest(N=N, t=t, subset=subset), self.assertRaises(NonIntegerLagrangeError):
                    reconstruct(RING, {j: keys[j] for j in subset})

    def test_contributions_and_master_key_are_small(self):
        N, t = 3, 2
        dealt, _ = deal(N, t)
        secrets = [secret_of(shares, t) for shares in dealt]
        for secret in secrets:
            self.assertLessEqual(max(map(abs, centered(secret))), TAIL)
        master = [sum(column) % Q for column in zip(*secrets)]
        self.assertLessEqual(max(map(abs, centered(master))), N * TAIL)


if __name__ == "__main__":
    unittest.main()
