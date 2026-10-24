"""The concrete QPASE server S_i (Sec. IV-A to IV-E, Definition 12, Fig. 5-6).

S_i holds its DKG key share k_i and pk_i = a k_i + 2e_i, one UserRecord per registered user,
and at most M = capacity outsourced (Ct, C, i) per user. Outsource and Retrieve are authorized
by sig_Ct and sig_dsk under pk_u, as the paper prints them: Retrieve reaches all N servers,
while Login reaches only t.
"""

import hmac
import os
from collections.abc import Sequence
from dataclasses import dataclass

from ..index import ItemScan, ScanOutcome, scan_item
from ..params import Lattice
from ..primitives import toprf
from ..primitives.encoding import int_bytes, pack
from ..primitives.ring import Poly
from ..primitives.secret_sharing import genkey, genshare
from ..primitives.signature import verify
from .server import Server
from .types import (
    DKGShare,
    KeyUpdateShare,
    LoginProof,
    OutsourceRequest,
    ProtocolAbort,
    PublicParams,
    RegisterKeyMessage,
    RetrieveRequest,
    RetrieveResponse,
    ServerID,
    SessionID,
    TOPRFRequest,
    TOPRFResponse,
    UserID,
    UserRecord,
)

SESSION_ID_SIZE = 32


@dataclass(frozen=True, slots=True, kw_only=True)
class ServerKey:
    """S_i's TOPRF key share k_i from Genkey and its public key pk_i = a k_i + 2e_i."""

    k_i: Poly
    pk_i: Poly


@dataclass(frozen=True, slots=True, kw_only=True)
class RetrieveScan:
    """R2 at one S_i: the check of every item it stores for the user, and the list L_i it returns."""

    server_id: ServerID
    items: tuple[ItemScan, ...]
    response: RetrieveResponse


class QPASEServer(Server):
    """S_i for the lattice TOPRF, ML-DSA-44 and AES-256-GCM. Single-keyword search only."""

    def __init__(self, pp: PublicParams, server_id: ServerID, capacity: int = 1000) -> None:
        """capacity is M, the storage slots S_i provides per user."""
        super().__init__(pp, server_id)
        self._lattice = Lattice.from_pp(pp)
        if not 1 <= server_id <= pp.N:
            raise ValueError(f"server id must be in [1, {pp.N}], got {server_id}")
        if capacity < 1:
            raise ValueError(f"capacity must be positive, got {capacity}")
        self.capacity = capacity
        self.key: ServerKey | None = None
        """None until the DKG has run."""
        self._sessions: dict[UserID, SessionID] = {}

    def dkg_genshare(self) -> dict[ServerID, DKGShare]:
        """Genshare: [s_i]_j = f_i(j) for every S_j, this server included."""
        ring = self._lattice.ring
        shares = genshare(ring, self.pp.t, range(1, self.pp.N + 1), self.pp.sigma)
        return {
            j: DKGShare(sender=self.server_id, receiver=j, share=ring.to_bytes(share)) for j, share in shares.items()
        }

    def dkg_genkey(self, shares: Sequence[DKGShare]) -> None:
        """Genkey: k_i = sum_j [s_j]_i over one share from each of the N servers, then pk_i."""
        if sorted(s.sender for s in shares) != list(range(1, self.pp.N + 1)):
            raise ProtocolAbort(f"need exactly one DKG share from each of the {self.pp.N} servers")
        if any(s.receiver != self.server_id for s in shares):
            raise ProtocolAbort(f"a DKG share is not addressed to S_{self.server_id}")
        ring = self._lattice.ring
        try:
            k_i = genkey(ring, [ring.from_bytes(s.share, (ring.n,)) for s in shares])
        except ValueError as error:
            raise ProtocolAbort(f"malformed DKG share: {error}") from error
        self.key = ServerKey(k_i=k_i, pk_i=toprf.server_public_key(ring, self._lattice.a, k_i, self.pp.sigma))

    def toprf_evaluate(self, request: TOPRFRequest) -> TOPRFResponse:
        """b_{k_i} = b k_i + 2e'_i.

        Login L1 (the user has a pk_u): abort if mu_u >= mu, then mu_u += 1, and return pk_u and sigma.
        Register step 1 (no pk_u yet) is not counted.
        """
        if self.key is None:
            raise ProtocolAbort(f"S_{self.server_id} has no key share: run the DKG first")
        record = self.users.get(request.user_id)
        if record is None:
            raise ProtocolAbort(f"unknown user {request.user_id!r}")
        ring = self._lattice.ring
        try:
            b = ring.from_bytes(request.blinded_input, (ring.ell, ring.n))
        except ValueError as error:
            raise ProtocolAbort(f"malformed blinded input: {error}") from error
        if record.user_pk is not None:
            if record.fail_count >= self.pp.mu:
                raise ProtocolAbort(f"mu_u = {record.fail_count} reached the limit mu = {self.pp.mu}")
            record.fail_count += 1
        return TOPRFResponse(
            server_id=self.server_id,
            evaluation=ring.to_bytes(toprf.evaluate(ring, b, self.key.k_i, self.pp.sigma)),
            server_pk=ring.to_bytes(self.key.pk_i),
            user_pk=record.user_pk,
            hint=record.hint,
        )

    def register_user(self, user_id: UserID) -> None:
        """Register step 1: reject a duplicate ID_u, else store it."""
        if user_id in self.users:
            raise ProtocolAbort(f"{user_id!r} is already registered")
        self.users[user_id] = UserRecord(user_id=user_id)

    def register_store_key(self, message: RegisterKeyMessage) -> None:
        """Register step 3: store pk_u and sigma, and set mu_u = 0."""
        record = self.users.get(message.user_id)
        if record is None or record.user_pk is not None:
            raise ProtocolAbort(f"{message.user_id!r} is not waiting for Register step 3")
        try:
            self._lattice.ring.unpack_bits(message.hint)
        except ValueError as error:
            raise ProtocolAbort(f"malformed hint: {error}") from error
        record.user_pk = message.user_pk
        record.hint = message.hint
        record.fail_count = 0

    def new_session(self, user_id: UserID) -> SessionID:
        """A fresh sid for L2. It replaces any sid still outstanding for this user."""
        self._registered(user_id)
        sid = os.urandom(SESSION_ID_SIZE)
        self._sessions[user_id] = sid
        return sid

    def login_verify(self, proof: LoginProof) -> bool:
        """L3: the outstanding sid is consumed; accept iff it matches and Ver(pk_u, (ID_u, sid), sig_u).

        On failure mu_u += 1.
        """
        record = self._registered(proof.user_id)
        sid = self._sessions.pop(proof.user_id, None)
        accepted = (
            sid is not None
            and hmac.compare_digest(sid, proof.session_id)
            and verify(record.user_pk, pack(proof.user_id.encode(), proof.session_id), proof.signature)
        )
        if not accepted:
            record.fail_count += 1
        return accepted

    def outsource_store(self, request: OutsourceRequest) -> bool:
        """O2: store (Ct, C, i) iff Ver(pk_u, (Ct, C, i), sig_Ct).

        An item with the same i is replaced and counts as the newest. When all M slots are full, the
        oldest item is evicted.
        """
        record = self._registered(request.user_id)
        item = request.item
        if not 0 <= item.item_id < 1 << 32:
            return False
        if not verify(record.user_pk, pack(item.index_ct, item.data_ct, int_bytes(item.item_id)), request.signature):
            return False
        kept = [stored for stored in self.storage.get(request.user_id, []) if stored.item_id != item.item_id]
        self.storage[request.user_id] = (kept + [item])[-self.capacity :]
        return True

    def retrieve_scan(self, request: RetrieveRequest) -> RetrieveScan:
        """R2: abort unless Ver(pk_u, dsk, sig_dsk); scan every stored item; L_i = the MATCH items."""
        record = self._registered(request.user_id)
        if not verify(record.user_pk, pack(*request.search_keys), request.signature):
            raise ProtocolAbort("sig_dsk does not verify under pk_u")
        if len(request.search_keys) != 1:
            raise ProtocolAbort(f"single-keyword queries only, got {len(request.search_keys)} search keys")
        (dsk,) = request.search_keys
        try:
            self._lattice.ring.unpack_bits(dsk)
        except ValueError as error:
            raise ProtocolAbort(f"malformed dsk: {error}") from error
        stored = self.storage.get(request.user_id, [])
        scans = tuple(scan_item(self._lattice, record.user_pk, dsk, item) for item in stored)
        matches = tuple(item for item, scan in zip(stored, scans) if scan.outcome is ScanOutcome.MATCH)
        return RetrieveScan(
            server_id=self.server_id, items=scans, response=RetrieveResponse(server_id=self.server_id, results=matches)
        )

    def retrieve_search(self, request: RetrieveRequest) -> RetrieveResponse:
        return self.retrieve_scan(request).response

    def key_update_shares(self) -> dict[ServerID, KeyUpdateShare]:
        raise NotImplementedError("server key update (Sec. IV-F) is unit U5")

    def key_update_apply(self, shares: Sequence[KeyUpdateShare]) -> None:
        raise NotImplementedError("server key update (Sec. IV-F) is unit U5")

    def _registered(self, user_id: UserID) -> UserRecord:
        """The record of a user who completed Register, else abort."""
        record = self.users.get(user_id)
        if record is None or record.user_pk is None:
            raise ProtocolAbort(f"{user_id!r} is not registered")
        return record
