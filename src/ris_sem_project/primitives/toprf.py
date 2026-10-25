"""The variant TOPRF Pi_TOPRF (Fig. 1-2, Theorem 1, Section II-B).

All noise is even (2e, 2e_i, 2e'_i as in Fig. 2) and the messages b, b_{k_i}, pk_i are
not rounded (as in Fig. 1 and Fig. 5). The user combines t responses into
F = a_x K + 2e'' and extracts K_u = E(F, sigma) with Ding's extractor (Definition 8).
The hint sigma = S(F_reg) is computed once at Register and reused at every Login, so
F_login - F_reg is even and small and K_u repeats (plan decisions 3 and 4).
"""

from . import extractor
from .ring import Bits, Poly, Ring
from .sampling import gaussian
from .secret_sharing import reconstruct


def blind(ring: Ring, a: Poly, ax: Poly, sigma: float) -> tuple[Poly, Poly]:
    """U: r <- chi_sigma, e <- chi_sigma^{1 x ell}, b = a r + a_x + 2e. Returns (b, r)."""
    r = gaussian(ring, (ring.n,), sigma)
    e = gaussian(ring, ax.shape, sigma)
    return (ring.mul(a, r) + ax + 2 * e) % ring.q, r


def server_public_key(ring: Ring, a: Poly, k_i: Poly, sigma: float) -> Poly:
    """S_i: pk_i = a k_i + 2e_i with e_i <- chi_sigma^{1 x ell}."""
    return (ring.mul(a, k_i) + 2 * gaussian(ring, a.shape, sigma)) % ring.q


def evaluate(ring: Ring, b: Poly, k_i: Poly, sigma: float) -> Poly:
    """S_i: b_{k_i} = b k_i + 2e'_i with e'_i <- chi_sigma^{1 x ell}."""
    return (ring.mul(b, k_i) + 2 * gaussian(ring, b.shape, sigma)) % ring.q


def combine(ring: Ring, evaluations: dict[int, Poly], public_keys: dict[int, Poly], r: Poly) -> Poly:
    """U: F = sum_i lambda_i b_{k_i} - r sum_i lambda_i pk_i = a_x K + 2e''.

    e'' = eK + sum_i lambda_i e'_i - r sum_i lambda_i e_i. The minus sign is what the
    algebra of Theorem 1's proof gives (plan decision 3). lambda_i are the Lagrange
    coefficients at 0 of the responding ids, so a subset such as {1, 3}, whose
    coefficients are not integers, raises NonIntegerLagrangeError.
    """
    return ring.sub(reconstruct(ring, evaluations), ring.mul(reconstruct(ring, public_keys), r))


def finalize(ring: Ring, F: Poly, hint: Bits | None = None) -> tuple[bytes, Bits]:
    """K_u = E(F, sigma) packed as ell * n bits, returned with the (ell, n) hint sigma.

    Register passes no hint and stores sigma = S(F). Login passes the stored sigma.
    """
    if hint is None:
        hint = extractor.hint(ring, F)
    return ring.pack_bits(extractor.extract(ring, F, hint)), hint
