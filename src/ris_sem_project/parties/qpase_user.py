"""The concrete QPASE user U (Sec. IV-B to IV-E, Fig. 5-6).

U's lifecycle is one phase value: idle (only ID_u and psw_u), a TOPRF in flight, a Register
waiting to send its hint, or a logged-in session holding K_u and the keys derived from it.
Every key comes from K_u through one lattice HKDF h = Hkdf(K_u):
dsk = h("QPASE/dsk/" || w), the AES key for C = h("QPASE/enc"), the Dilithium seed = h("QPASE/sig").
"""

from collections.abc import Sequence
from dataclasses import dataclass, field

import numpy as np

from ..index import ItemScan, ScanOutcome, build_item, scan_item
from ..params import Lattice
from ..primitives import toprf
from ..primitives.bp_prf import encode_input
from ..primitives.encoding import int_bytes, pack
from ..primitives.hkdf import Hkdf
from ..primitives.ring import Bits, Poly
from ..primitives.secret_sharing import lagrange_at_zero
from ..primitives.signature import keypair_from_seed, sign
from ..primitives.symmetric import aes_key, decrypt
from .types import (
    Keyword,
    LoginProof,
    OutsourceRequest,
    ProtocolAbort,
    PublicParams,
    RegisterKeyMessage,
    RetrieveRequest,
    RetrieveResponse,
    ServerID,
    SessionID,
    StoredItem,
    TOPRFRequest,
    TOPRFResponse,
    UserID,
)
from .user import User


@dataclass(frozen=True, slots=True, kw_only=True)
class OpenedItem:
    """R3 for one distinct item the servers returned: U's own check and, on MATCH, d = Dec(K_u, C)."""

    item_id: int
    server_ids: tuple[ServerID, ...]
    """The servers whose L_i held this item."""
    scan: ItemScan
    data: bytes | None
    """d, or None unless scan.outcome is MATCH."""


@dataclass(frozen=True, slots=True, kw_only=True)
class _Blinded:
    """TOPRF in flight: the blinding r and the servers that were sent b."""

    r: Poly
    server_ids: frozenset[ServerID]


@dataclass(frozen=True, slots=True, kw_only=True)
class _Registering:
    """Register step 1 done: K_u and the fresh hint sigma, until step 2 sends sigma with pk_u."""

    k_u: bytes
    hint: Bits


@dataclass(slots=True, kw_only=True)
class _Session:
    """Logged in: K_u, its HKDF, (pk_u, sk_u), the AES key for C, and each dsk derived so far."""

    k_u: bytes
    hkdf: Hkdf
    pk: bytes
    sk: bytes
    k_enc: bytes
    search_keys: dict[Keyword, bytes] = field(default_factory=dict)


class QPASEUser(User):
    """U with the lattice TOPRF, ML-DSA-44 and AES-256-GCM. Single-keyword search only."""

    def __init__(self, pp: PublicParams, user_id: UserID, password: str) -> None:
        super().__init__(pp, user_id, password)
        self._lattice = Lattice.from_pp(pp)
        self._phase: _Blinded | _Registering | _Session | None = None

    def encode_password(self, password: str) -> bytes:
        """x = the first L bits of SHA3-256(psw_u), packed."""
        return np.packbits(encode_input(password.encode(), self.pp.L)).tobytes()

    def toprf_request(self, server_ids: Sequence[ServerID]) -> dict[ServerID, TOPRFRequest]:
        """b = a r + a_x + 2e, the same b to every contacted S_i (Fig. 2).

        Raise ValueError, before any server is contacted, unless server_ids are at least t distinct
        servers whose Lagrange coefficients at 0 are integers (plan decision 3).
        """
        ids = tuple(server_ids)
        if len(set(ids)) != len(ids) or not all(1 <= i <= self.pp.N for i in ids) or len(ids) < self.pp.t:
            raise ValueError(f"need at least t = {self.pp.t} distinct ids in [1, {self.pp.N}], got {ids}")
        lagrange_at_zero(ids)
        ring = self._lattice.ring
        ax = self._lattice.prf.a_x(encode_input(self.password.encode(), self.pp.L))
        b, r = toprf.blind(ring, self._lattice.a, ax, self.pp.sigma)
        self._phase = _Blinded(r=r, server_ids=frozenset(ids))
        return {i: TOPRFRequest(user_id=self.user_id, blinded_input=ring.to_bytes(b)) for i in ids}

    def toprf_finalize(self, responses: Sequence[TOPRFResponse]) -> bytes:
        """K_u = E(F, sigma) for F = sum_i lambda_i b_{k_i} - r sum_i lambda_i pk_i.

        Register (no hint in any response): sigma = S(F), kept for register_keygen.
        Login (a hint in every response): all hints must be equal; sigma is that hint.
        """
        phase = self._phase
        if not isinstance(phase, _Blinded):
            raise ProtocolAbort("no TOPRF in flight")
        by_id = {response.server_id: response for response in responses}
        if len(by_id) != len(responses) or by_id.keys() != phase.server_ids:
            raise ProtocolAbort(f"need one response from each of {sorted(phase.server_ids)}")
        hints = {response.hint for response in responses}
        if len(hints) != 1:
            raise ProtocolAbort("servers returned different hints")
        (packed_hint,) = hints
        ring = self._lattice.ring
        shape = (ring.ell, ring.n)
        try:
            evaluations = {i: ring.from_bytes(response.evaluation, shape) for i, response in by_id.items()}
            public_keys = {i: ring.from_bytes(response.server_pk, shape) for i, response in by_id.items()}
            hint = None if packed_hint is None else ring.unpack_bits(packed_hint)
        except ValueError as error:
            raise ProtocolAbort(f"malformed TOPRF response: {error}") from error
        k_u, hint = toprf.finalize(ring, toprf.combine(ring, evaluations, public_keys, phase.r), hint)
        self._phase = _Registering(k_u=k_u, hint=hint) if packed_hint is None else None
        return k_u

    def register_keygen(self, k_u: bytes) -> RegisterKeyMessage:
        """Register step 2: (pk_u, sk_u) <- Gen(1^kappa, K_u), send pk_u and sigma.

        Step 4: U then keeps only (ID_u, psw_u); K_u and sk_u are dropped.
        """
        phase = self._phase
        if not (isinstance(phase, _Registering) and phase.k_u == k_u):
            raise ProtocolAbort("register_keygen needs the K_u just extracted at Register")
        pk, _ = _signing_keys(Hkdf(self._lattice.prf, k_u))
        self._phase = None
        return RegisterKeyMessage(user_id=self.user_id, user_pk=pk, hint=self._lattice.ring.pack_bits(phase.hint))

    def login_verify(self, k_u: bytes, stored_pk: bytes, session_id: SessionID) -> LoginProof:
        """L2: (pk_u', sk_u') <- Gen(1^kappa, K_u); abort unless pk_u' == pk_u, else sig_u = Sign(sk_u', (ID_u, sid)).

        The keys are derived once per K_u, so the t contacted servers share one derivation.
        """
        session = self._phase
        if not (isinstance(session, _Session) and session.k_u == k_u):
            hkdf = Hkdf(self._lattice.prf, k_u)
            pk, sk = _signing_keys(hkdf)
            session = _Session(k_u=k_u, hkdf=hkdf, pk=pk, sk=sk, k_enc=aes_key(hkdf.derive(b"QPASE/enc")))
        if session.pk != stored_pk:
            self._phase = None
            raise ProtocolAbort("pk_u' != pk_u: wrong password, re-enter it and run L1 again")
        self._phase = session
        signature = sign(session.sk, pack(self.user_id.encode(), session_id))
        return LoginProof(user_id=self.user_id, session_id=session_id, signature=signature)

    def search_key(self, keyword: Keyword) -> bytes:
        """dsk = HKDF(K_u, w)."""
        session = self._session()
        if keyword not in session.search_keys:
            session.search_keys[keyword] = session.hkdf.derive(b"QPASE/dsk/" + keyword.encode())
        return session.search_keys[keyword]

    def outsource(self, keyword: Keyword, data: bytes, item_id: int) -> OutsourceRequest:
        """O1: (Ct, C, i) from build_item and sig_Ct = Sign(sk_u, (Ct, C, i))."""
        if not 0 <= item_id < 1 << 32:
            raise ValueError(f"item id must fit in 4 bytes, got {item_id}")
        session = self._session()
        item = build_item(self._lattice, session.sk, session.k_enc, self.search_key(keyword), data, item_id)
        signature = sign(session.sk, pack(item.index_ct, item.data_ct, int_bytes(item_id)))
        return OutsourceRequest(user_id=self.user_id, item=item, signature=signature)

    def retrieve_request(self, keywords: Sequence[Keyword]) -> RetrieveRequest:
        """R1: dsk = HKDF(K_u, w) and sig_dsk = Sign(sk_u, dsk)."""
        session = self._session()
        search_keys = (self.search_key(_single(keywords)),)
        signature = sign(session.sk, pack(*search_keys))
        return RetrieveRequest(user_id=self.user_id, search_keys=search_keys, signature=signature)

    def retrieve_open(self, keywords: Sequence[Keyword], responses: Sequence[RetrieveResponse]) -> list[OpenedItem]:
        """R3: check each distinct returned item under U's own dsk, and decrypt C on MATCH. Ordered by item id.

        Items are merged by value, so one item held by several servers is opened once, while two
        different items under the same id are both kept.
        """
        session = self._session()
        dsk = self.search_key(_single(keywords))
        sources: dict[StoredItem, list[ServerID]] = {}
        for response in responses:
            for item in response.results:
                sources.setdefault(item, []).append(response.server_id)
        opened = []
        for item, server_ids in sources.items():
            scan = scan_item(self._lattice, session.pk, dsk, item)
            data = decrypt(session.k_enc, item.data_ct) if scan.outcome is ScanOutcome.MATCH else None
            opened.append(OpenedItem(item_id=item.item_id, server_ids=tuple(server_ids), scan=scan, data=data))
        return sorted(opened, key=lambda o: o.item_id)

    def retrieve_finalize(self, keywords: Sequence[Keyword], responses: Sequence[RetrieveResponse]) -> list[bytes]:
        """R3: every d whose item matched, ordered by item id."""
        return [o.data for o in self.retrieve_open(keywords, responses) if o.data is not None]

    def _session(self) -> _Session:
        if not isinstance(self._phase, _Session):
            raise ProtocolAbort("not logged in")
        return self._phase


def _signing_keys(hkdf: Hkdf) -> tuple[bytes, bytes]:
    """(pk_u, sk_u) = Gen(1^kappa, K_u), seeded with the first 32 bytes of HKDF(K_u, "QPASE/sig")."""
    return keypair_from_seed(aes_key(hkdf.derive(b"QPASE/sig")))


def _single(keywords: Sequence[Keyword]) -> Keyword:
    if len(keywords) != 1:
        raise ValueError(f"single-keyword queries only (Sec. IV-G is not implemented), got {len(keywords)} keywords")
    return keywords[0]
