import unittest

import numpy as np

from ris_sem_project.primitives.extractor import extract, hint
from ris_sem_project.primitives.ring import Ring

Q = 2**28 - 57
H = (Q - 1) // 2
QUARTER = Q // 4
RING = Ring(Q, 8)
RNG = np.random.default_rng(8)


class ExtractorTest(unittest.TestCase):
    def test_even_perturbations_below_q_over_8_keep_every_bit(self):
        edges = np.array([0, 1, -1, H, -H, *(s * (QUARTER + d) for s in (1, -1) for d in (-1, 0, 1, 2))]) % Q
        random_y, edge_y = RNG.integers(0, Q, 200_000), np.repeat(edges, 200)
        bound = Q // 16
        y = np.concatenate([random_y, edge_y])
        e = np.concatenate([RNG.integers(-bound, bound + 1, random_y.size), np.resize([bound, -bound], edge_y.size)])
        sigma = hint(RING, y)
        mismatches = extract(RING, (y + 2 * e) % Q, sigma) != extract(RING, y, sigma)
        self.assertEqual(np.count_nonzero(mismatches), 0)

    def test_extract_is_the_parity_of_the_centered_shift(self):
        zero, one = np.zeros(4, dtype=np.uint8), np.ones(4, dtype=np.uint8)
        self.assertEqual(extract(RING, np.array([3, 4, Q - 1, Q - 2]), zero).tolist(), [1, 0, 1, 0])
        self.assertEqual(extract(RING, np.array([H + 1, H + 3, H, 0]), one).tolist(), [0, 0, 1, H % 2])

    def test_hint_is_fixed_away_from_the_signal_boundaries(self):
        y = np.repeat(np.array([0, 1, Q - 1, H, H + 1]), 100)
        sigma = hint(RING, y).reshape(5, 100)
        self.assertEqual(sigma.min(axis=1).tolist(), [0, 0, 0, 1, 1])
        self.assertEqual(sigma.max(axis=1).tolist(), [0, 0, 0, 1, 1])

    def test_hint_is_a_fair_coin_where_the_two_signals_disagree(self):
        y = np.repeat(np.array([QUARTER + 1, -QUARTER % Q]), 4000)
        for frequency in hint(RING, y).reshape(2, 4000).mean(axis=1):
            self.assertAlmostEqual(frequency, 0.5, delta=0.05)


if __name__ == "__main__":
    unittest.main()
