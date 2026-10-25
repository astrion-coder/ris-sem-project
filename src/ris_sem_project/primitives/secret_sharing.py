"""Shamir sharing over R_q and the distributed key generation of Definitions 11-12 [83].

Sharing polynomials have degree t - 1, so any t of the N servers suffice (plan
decision 5). Each contribution s_i is drawn from chi_sigma, so the master key
K = sum_i s_i is small. Only integer Lagrange coefficients are allowed. Both keep the
TOPRF noise small (plan decision 3).
"""

import math
from collections.abc import Iterable, Mapping
from fractions import Fraction

import numpy as np

from .ring import Poly, Ring
from .sampling import gaussian, uniform


class NonIntegerLagrangeError(ValueError):
    """Some Lagrange coefficient at 0 of the chosen ids is not an integer."""


def lagrange_at_zero(ids: Iterable[int]) -> dict[int, int]:
    """lambda_i = prod_{j != i} j / (j - i), so f(0) = sum_i lambda_i f(i) when deg f < len(ids).

    Raise NonIntegerLagrangeError if any lambda_i is not an integer.
    """
    ids = tuple(ids)
    coefficients = {}
    for i in ids:
        lam = math.prod((Fraction(j, j - i) for j in ids if j != i), start=Fraction(1))
        if lam.denominator != 1:
            raise NonIntegerLagrangeError(f"lambda_{i} = {lam} for ids {sorted(ids)}")
        coefficients[i] = lam.numerator
    return coefficients


def genshare(ring: Ring, t: int, ids: Iterable[int], sigma: float) -> dict[int, Poly]:
    """Genshare at S_i: f_i(X) = s_i + sum_{k=1}^{t-1} c_k X^k, s_i <- chi_sigma, c_k <- R_q.

    Returns [s_i]_j = f_i(j) for every server id j.
    """
    coefficients = [gaussian(ring, (ring.n,), sigma)] + [uniform(ring, (ring.n,)) for _ in range(t - 1)]
    shares = {}
    for j in ids:
        value = np.zeros(ring.n, dtype=np.int64)
        for c in reversed(coefficients):
            value = (value * j + c) % ring.q
        shares[j] = value
    return shares


def genkey(ring: Ring, shares: Iterable[Poly]) -> Poly:
    """Genkey at S_j: k_j = sum_i [s_i]_j."""
    return sum(shares, np.zeros(ring.n, dtype=np.int64)) % ring.q


def reconstruct(ring: Ring, shares: Mapping[int, Poly]) -> Poly:
    """sum_i lambda_i share_i mod q, the value at 0 of the polynomial through the shares."""
    lam = lagrange_at_zero(shares)
    return sum((lam[i] % ring.q) * share % ring.q for i, share in shares.items()) % ring.q
