"""Parameter sets (Table II) and Setup (Section IV-A).

Table II fixes q and n. The paper leaves p, sigma and L open, set here as in plan
decision 7: p = 2 (the extractor outputs bits), sigma = 3.2, and L = kappa = 128.
"""

from dataclasses import dataclass

from .parties.types import PublicParams
from .primitives.bp_prf import BPPRF
from .primitives.ring import Poly, Ring
from .primitives.sampling import uniform


@dataclass(frozen=True, slots=True, kw_only=True)
class ParamSet:
    """One parameter set of Table II, completed with p, sigma and L."""

    name: str
    q: int
    n: int
    p: int
    """Rounding modulus of the BP PRF."""
    sigma: float
    """Standard deviation of chi_sigma."""
    L: int
    """Bit length of the PRF and TOPRF inputs x in {0,1}^L."""


PARAM_I = ParamSet(name="PARAM I", q=2**28 - 57, n=512, p=2, sigma=3.2, L=128)
"""100-bit classical and 92-bit quantum security (BKZ block size 342). The default."""

PARAM_II = ParamSet(name="PARAM II", q=2**28 - 57, n=595, p=2, sigma=3.2, L=128)
"""140-bit classical and 128-bit quantum security (BKZ block size 478), used in the paper's experiments.

595 is not a power of two, so X^595 + 1 is not a cyclotomic polynomial. This code still
uses Z_q[X]/(X^595 + 1), the ring of the scheme text (plan decision 1); the paper's estimate
for n = 595 likely assumes plain LWE. In this ring, because 595 is odd, X = -1 is a root, so
a -> a(-1) maps R_q onto Z_q and shrinks each ring-LWE sample to a one-dimensional one. A
server can then test password guesses offline against one blinded TOPRF request
(root_attack.py, notebook 06). Use PARAM I where security matters.
"""


def setup(params: ParamSet = PARAM_I, *, N: int, t: int, mu: int) -> PublicParams:
    """pp <- Setup(1^kappa): uniform a, a_0, a_1 in R_q^{1 x ell} and the server settings N, t, mu."""
    _check_servers(N, t, mu)
    ring = Ring(params.q, params.n)
    a, a0, a1 = (ring.to_bytes(uniform(ring, (ring.ell, ring.n))) for _ in range(3))
    return PublicParams(
        q=params.q,
        p=params.p,
        n=params.n,
        ell=ring.ell,
        L=params.L,
        sigma=params.sigma,
        N=N,
        t=t,
        mu=mu,
        a=a,
        a0=a0,
        a1=a1,
    )


def _check_servers(N: int, t: int, mu: int) -> None:
    if not 1 <= t <= N:
        raise ValueError(f"need 1 <= t <= N, got t={t}, N={N}")
    if mu < 1:
        raise ValueError(f"need mu >= 1, got mu={mu}")


@dataclass(frozen=True, slots=True, kw_only=True, eq=False)
class Lattice:
    """The lattice part of pp, parsed once: R_q, the public a, and the BP PRF on (a_0, a_1)."""

    ring: Ring
    a: Poly
    prf: BPPRF

    @classmethod
    def from_pp(cls, pp: PublicParams) -> Lattice:
        """Validate and parse pp. Raise ValueError if any field is malformed."""
        ring = Ring(pp.q, pp.n)
        if pp.ell != ring.ell:
            raise ValueError(f"ell must be ceil(log2 q) = {ring.ell}, got {pp.ell}")
        if pp.p != 2:
            raise ValueError(f"p must be 2, got {pp.p}")
        if not 1 <= pp.L <= 256:
            raise ValueError(f"L must be in [1, 256] (bits of SHA3-256), got {pp.L}")
        if not pp.sigma > 0:
            raise ValueError(f"sigma must be positive, got {pp.sigma}")
        _check_servers(pp.N, pp.t, pp.mu)
        shape = (ring.ell, ring.n)
        a0, a1 = ring.from_bytes(pp.a0, shape), ring.from_bytes(pp.a1, shape)
        return cls(ring=ring, a=ring.from_bytes(pp.a, shape), prf=BPPRF(ring, a0, a1, pp.L))
