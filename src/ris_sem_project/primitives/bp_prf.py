"""The Banerjee-Peikert lattice PRF F_k(x) = round_p(a_x * k) (Lemma 1, [80], Section II-B).

a_x = a_{x_1} G^{-1}(a_{x_2} G^{-1}( ... G^{-1}(a_{x_L}))) for x in {0,1}^L and public
a_0, a_1 in R_q^{1 x ell}. With p = 2 every coefficient of a_x * k rounds to one bit.
"""

import hashlib

import numpy as np

from .gadget import g_inverse
from .ring import Bits, Poly, Ring


def encode_input(data: bytes, L: int) -> Bits:
    """x in {0,1}^L: the first L bits of SHA3-256(data), most significant bit first."""
    return np.unpackbits(np.frombuffer(hashlib.sha3_256(data).digest(), dtype=np.uint8))[:L]


class BPPRF:
    """F_k(x) for the public (a_0, a_1) of pp and inputs x in {0,1}^L."""

    def __init__(self, ring: Ring, a0: Poly, a1: Poly, L: int) -> None:
        self.ring = ring
        self.L = L
        self._a = (a0, a1)
        self._spectra = (ring.limb_spectra(a0), ring.limb_spectra(a1))

    def a_x(self, x: Bits) -> Poly:
        """a_x in R_q^{1 x ell}: start from a_{x_L}, then v = a_{x_i} G^{-1}(v) for i = L-1, ..., 1."""
        v = self._a[x[-1]]
        for bit in x[-2::-1]:
            decomposition = self.ring.spectrum(g_inverse(self.ring, v))
            lo, hi = self.ring.from_spectrum(np.einsum("lkf,kjf->ljf", self._spectra[bit], decomposition))
            v = self.ring.join_limbs(lo, hi)
        return v

    def evaluate(self, k: Poly, x: Bits) -> Bits:
        """F_k(x) = round_2(a_x * k), round_2(y) = floor((2y + floor(q/2)) / q) mod 2, as ell * n bits."""
        y = self.ring.mul(self.a_x(x), k)
        q = self.ring.q
        return ((2 * y + q // 2) // q % 2).astype(np.uint8).reshape(-1)
