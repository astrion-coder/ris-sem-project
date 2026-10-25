"""PRF: K_u x {0,1}^K -> {0,1}^K of Setup (Section IV-A), used as v = PRF(dsk, rho) in
Outsource and Retrieve, instantiated with the BP lattice PRF (Lemma 1, [80]).

A key is an ell * n bit string (K_u, dsk, PRK), packed as by Ring.pack_bits.
"""

import numpy as np

from .bp_prf import BPPRF, encode_input
from .ring import Poly, Ring


def key_to_ring(ring: Ring, key: bytes) -> Poly:
    """The R_q element whose coefficient i is bits [i ell, (i+1) ell) of key, big-endian, mod q.

    Raise ValueError if key is not an ell * n bit string.
    """
    groups = ring.unpack_bits(key).reshape(ring.n, ring.ell).astype(np.int64)
    weights = 1 << np.arange(ring.ell - 1, -1, -1, dtype=np.int64)
    return (groups @ weights) % ring.q


def prf(bp: BPPRF, key: bytes, data: bytes) -> bytes:
    """F_key(x) as packed ell * n bits, for x = the first L bits of SHA3-256(data)."""
    return bp.ring.pack_bits(bp.evaluate(key_to_ring(bp.ring, key), encode_input(data, bp.L)))
