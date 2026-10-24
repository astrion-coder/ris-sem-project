"""Ding et al.'s robust extractor (Definition 8, [69]): the hint S and the extractor E.

Both work per coefficient on centered representatives in [-(q-1)/2, (q-1)/2], q odd.
If x - y is even and small, E(x, sigma) = E(y, sigma) for sigma <- S(y).
"""

import numpy as np

from .ring import Bits, Poly, Ring
from .sampling import random_bits


def hint(ring: Ring, y: Poly) -> Bits:
    """sigma <- S(y): sigma_b(y) per coefficient for a uniform b in {0, 1}.

    sigma_0(c) = 0 iff c in [-floor(q/4), floor(q/4)], and
    sigma_1(c) = 0 iff c in [-floor(q/4) + 1, floor(q/4) + 1].
    """
    c = ring.centered(y)
    b = random_bits(c.shape).astype(np.int64)
    quarter = ring.q // 4
    return ((c < b - quarter) | (c > b + quarter)).astype(np.uint8)


def extract(ring: Ring, x: Poly, sigma: Bits) -> Bits:
    """E(x, sigma) = centered(x + sigma (q-1)/2 mod q) mod 2.

    The paper prints (x + sigma) (q-1)/2 mod 2. That is a typesetting slip: the
    robustness property of Definition 8 holds for Ding's definition, used here.
    """
    shifted = ring.centered(x + sigma.astype(np.int64) * ((ring.q - 1) // 2))
    return (shifted % 2).astype(np.uint8)
