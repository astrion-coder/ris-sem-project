"""The linear hash H of the key update commitments (Sec. IV-F, plan decision 6).

Step 4 checks H(F_ji) = sum_k i^k H(alpha_k), which a generic collision-resistant hash cannot
satisfy. H(x) = A_H x mod q is linear, so H(sum_k i^k alpha_k) = sum_k i^k H(alpha_k) holds
exactly. x in R_q is read as its n coefficients and A_H in Z_q^{n x n} is public: it is expanded
from SHAKE256(b"QPASE/H") as 4-byte little-endian words masked to ell bits, keeping those below q,
filled row-major. Every party therefore derives the same matrix from (q, n) alone.

Known gap: A_H is square and, being random mod the prime q, invertible, so h_k = H(alpha_k)
reveals alpha_k to anyone who sees the broadcast commitments. An eavesdropper then knows every
F_ji and every key delta k_i' - k_i, and E(i, .) hides nothing. Verification, binding and Lemma 3
still hold. A compressing A_H would hide alpha_k but lose binding for uniform inputs; a hiding,
binding, homomorphic lattice commitment needs randomness the paper's H does not have.
"""

import hashlib
from functools import cache

import numpy as np
from numpy.typing import NDArray

from .ring import LIMB_BITS, Poly, Ring

SEED = b"QPASE/H"

WORD_SIZE = 4


@cache
def _matrix(q: int, n: int) -> NDArray[np.int64]:
    """A_H: the first n * n accepted words of SHAKE256(SEED), as an (n, n) array."""
    mask = (1 << (q - 1).bit_length()) - 1
    count = n * n
    words = count
    while True:
        raw = hashlib.shake_256(SEED).digest(WORD_SIZE * words)
        draws = np.frombuffer(raw, dtype="<u4").astype(np.int64) & mask
        accepted = draws[draws < q]
        if accepted.size >= count:
            matrix = accepted[:count].reshape(n, n)
            matrix.setflags(write=False)
            return matrix
        words *= 2


def linear_hash(ring: Ring, x: Poly) -> Poly:
    """H(x) = A_H x mod q, for x of shape (..., n) with coefficients in [0, q).

    The product is exact: x splits into two 14-bit limbs, so each partial sum stays below
    n * 2^42, far under 2^63, whereas the unsplit sums reach n * 2^56.
    """
    if x.shape[-1:] != (ring.n,):
        raise ValueError(f"expected {ring.n} coefficients on the last axis, got shape {x.shape}")
    a = _matrix(ring.q, ring.n)
    lo = (x & ((1 << LIMB_BITS) - 1)) @ a.T
    hi = (x >> LIMB_BITS) @ a.T
    return ring.join_limbs(lo, hi)
