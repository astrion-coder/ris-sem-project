"""CRYSTALS-Dilithium signature (Definition 13), instantiated as ML-DSA-44.

Gen(1^kappa, K_u) is realised by `keypair_from_seed`: the caller turns the
password-derived K_u into a 32-byte seed, so the same password re-derives the
same (pk_u, sk_u) at every Login.
"""

from dilithium_py.ml_dsa import ML_DSA_44

SEED_SIZE = 32


def keypair_from_seed(seed: bytes) -> tuple[bytes, bytes]:
    """Deterministic Gen: return (pk, sk) from a 32-byte seed."""
    if len(seed) != SEED_SIZE:
        raise ValueError(f"seed must be {SEED_SIZE} bytes, got {len(seed)}")
    return ML_DSA_44.key_derive(seed)


def sign(sk: bytes, message: bytes) -> bytes:
    """Sig(sk, m), randomized."""
    return ML_DSA_44.sign(sk, message)


def verify(pk: bytes, message: bytes, signature: bytes) -> bool:
    """Ver(pk, m, sigma). Never raises: inputs come from another party."""
    try:
        return bool(ML_DSA_44.verify(pk, message, signature))
    except Exception:
        return False
