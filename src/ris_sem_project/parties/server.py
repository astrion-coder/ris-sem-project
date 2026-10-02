"""The QPASE server S_i (Section III-A), one of S = {S_1, ..., S_N}.

Each S_i holds a share k_i of the TOPRF master key K (never reconstructed),
the per-user registration records, and the outsourced ciphertexts. The model
is semi-honest; an adversary may corrupt at most t' < t servers.
"""

from abc import abstractmethod
from collections.abc import Sequence

from .base import Party
from .types import (
    DKGShare,
    KeyUpdateShare,
    LoginProof,
    OutsourceRequest,
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
    UserRecord,
)


class Server(Party):
    """Abstract QPASE server. Implements RegisterS, LoginS, OutsourceS, RetrieveS,
    plus the server-only DKG and key-update protocols."""

    def __init__(self, pp: PublicParams, server_id: ServerID) -> None:
        super().__init__(pp)
        self.server_id = server_id
        self.epoch = 0
        """omega: the current key epoch."""
        self.users: dict[UserID, UserRecord] = {}
        self.storage: dict[UserID, list[StoredItem]] = {}

    # ---- Setup: distributed key generation (Definition 12) ----------------

    @abstractmethod
    def dkg_genshare(self) -> dict[ServerID, DKGShare]:
        """Genshare: sample this server's sharing polynomial and emit [s_i]_j for every S_j."""

    @abstractmethod
    def dkg_genkey(self, shares: Sequence[DKGShare]) -> None:
        """Genkey: set k_j = sum_i [s_i]_j and publish pk_j."""

    # ---- TOPRF server (shared by Register step 1 and Login step L1) -------

    @abstractmethod
    def toprf_evaluate(self, request: TOPRFRequest) -> TOPRFResponse:
        """Evaluate the blinded input under k_i.

        During Login, first enforce mu_u < mu (else raise :class:`ProtocolAbort`),
        increment mu_u, and include pk_u in the response (step L1).
        """

    # ---- Register (Section IV-B) ------------------------------------------

    @abstractmethod
    def register_user(self, user_id: UserID) -> None:
        """Register step 1: reject a duplicate ID_u, otherwise create its record."""

    @abstractmethod
    def register_store_key(self, message: RegisterKeyMessage) -> None:
        """Register step 3: store (ID_u, pk_u, k_i) and set mu_u = 0."""

    # ---- Login (Section IV-C) ---------------------------------------------

    @abstractmethod
    def new_session(self, user_id: UserID) -> SessionID:
        """Issue the sid that U must sign in step L2."""

    @abstractmethod
    def login_verify(self, proof: LoginProof) -> bool:
        """Login step L3: Ver(pk_u, (ID_u, sid), sig_u). On failure set mu_u += 1."""

    # ---- Outsource (Section IV-D) -----------------------------------------

    @abstractmethod
    def outsource_store(self, request: OutsourceRequest) -> bool:
        """Outsource step O2: Ver(pk_u, (Ct, C, i), sig_Ct); store (Ct, C, i) if valid."""

    # ---- Retrieve (Section IV-E) ------------------------------------------

    @abstractmethod
    def retrieve_search(self, request: RetrieveRequest) -> RetrieveResponse:
        """Retrieve step R2: verify sig_dsk, then for each stored Ct decrypt
        (rho, v, sig_C) under dsk and add (Ct, C, i) to L_i when sig_C verifies
        and v = PRF(dsk, rho)."""

    # ---- Server key update (Section IV-F) ---------------------------------

    @abstractmethod
    def key_update_shares(self) -> dict[ServerID, KeyUpdateShare]:
        """Steps 1-3: sample a zero-constant update polynomial [F] and send
        signed, committed shares F_ji to every S_i."""

    @abstractmethod
    def key_update_apply(self, shares: Sequence[KeyUpdateShare]) -> None:
        """Steps 4-5: verify the received shares, set k_i' = k_i + sum_j lambda_ij [F]_j^i,
        recompute pk_i', reset every mu_u and advance the epoch.

        The master key K is unchanged (Lemma 3), so users are unaffected.
        """
