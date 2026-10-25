"""Samplers over R_q and Z_q: uniform, and the discrete Gaussian chi_sigma (Definition 3).

sigma is the standard deviation, as the text of Definition 3 says. Its printed density
exp(-pi x^2 / sigma^2) would instead make sigma the width parameter, with standard
deviation sigma / sqrt(2 pi). All randomness comes from os.urandom and secrets.
"""

import decimal
import itertools
import math
import os
import secrets
from decimal import Decimal
from functools import cache

import numpy as np
from numpy.typing import NDArray

from .ring import Bits, Poly, Ring

TAIL = 12
"""chi_sigma is supported on |x| <= ceil(TAIL * sigma)."""


def random_bits(shape: tuple[int, ...]) -> Bits:
    """Independent uniform bits."""
    count = math.prod(shape)
    raw = np.frombuffer(os.urandom(-(-count // 8)), dtype=np.uint8)
    return np.unpackbits(raw)[:count].reshape(shape)


def uniform(ring: Ring, shape: tuple[int, ...]) -> Poly:
    """Coefficients uniform in [0, q): ell-bit draws, redrawing those >= q."""
    count = math.prod(shape)
    mask = (1 << ring.ell) - 1
    accepted = np.empty(0, dtype=np.int64)
    while accepted.size < count:
        raw = os.urandom(4 * (count - accepted.size))
        draws = np.frombuffer(raw, dtype="<u4").astype(np.int64) & mask
        accepted = np.concatenate([accepted, draws[draws < ring.q]])
    return accepted.reshape(shape)


def gaussian(ring: Ring, shape: tuple[int, ...], sigma: float) -> Poly:
    """x <- chi_sigma per coefficient, P(x) proportional to exp(-x^2 / (2 sigma^2)), mod q."""
    count = math.prod(shape)
    u = np.frombuffer(os.urandom(8 * count), dtype="<u8")
    magnitude = np.searchsorted(_magnitude_cdt(sigma), u, side="right").astype(np.int64)
    signed = np.where(random_bits((count,)) == 1, -magnitude, magnitude)
    return ring.small(signed.reshape(shape))


def uniform_zq(q: int) -> int:
    """An integer uniform in [0, q)."""
    return secrets.randbelow(q)


@cache
def _magnitude_cdt(sigma: float) -> NDArray[np.uint64]:
    """The cumulative distribution of |x| for x <- chi_sigma, as 64-bit thresholds.

    m > 0 has weight 2 rho(m), one per sign, and 0 has weight rho(0), so the sign
    that gaussian applies afterwards does not count 0 twice.
    """
    support = range(math.ceil(TAIL * sigma) + 1)
    with decimal.localcontext(prec=60):
        two_sigma_squared = 2 * Decimal(sigma) ** 2
        weights = [(Decimal(-m * m) / two_sigma_squared).exp() * (1 if m == 0 else 2) for m in support]
        total = sum(weights)
        thresholds = [int(c / total * 2**64) for c in itertools.accumulate(weights)]
    return np.array([t for t in thresholds if t < 2**64], dtype=np.uint64)
