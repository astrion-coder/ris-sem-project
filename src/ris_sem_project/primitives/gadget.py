"""The gadget G = (1, 2, ..., 2^{ell-1}) and its inverse G^{-1} (Section II-B)."""

import numpy as np

from .ring import Bits, Poly, Ring


def g_inverse(ring: Ring, v: Poly) -> Bits:
    """G^{-1}(v) for v in R_q^{1 x ell}: the binary B in R_q^{ell x ell} with G B = v.

    B has shape (ell, ell, n) and B[k, j] holds bit k of every coefficient of v_j,
    so sum_k 2^k B[k, j] = v_j.
    """
    shifts = np.arange(ring.ell).reshape(-1, 1, 1)
    return ((v >> shifts) & 1).astype(np.uint8)
