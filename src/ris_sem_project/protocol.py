"""Whole QPASE phases (Sec. IV-A to IV-E, Fig. 5-6), run by moving messages between parties.

Each function returns a record of every message it moved and what U computed from them, so a
notebook can show a run without re-implementing a step.
"""

from collections.abc import Mapping, Sequence
from dataclasses import dataclass

from .parties.qpase_server import QPASEServer, RetrieveScan
from .parties.qpase_user import OpenedItem, QPASEUser
from .parties.types import (
    DKGShare,
    Keyword,
    LoginProof,
    OutsourceRequest,
    ProtocolAbort,
    PublicParams,
    RegisterKeyMessage,
    RetrieveRequest,
    ServerID,
    TOPRFRequest,
    TOPRFResponse,
)


@dataclass(frozen=True, slots=True, kw_only=True)
class DKGRun:
    """The DKG among the N servers (Definition 12)."""

    shares: dict[ServerID, dict[ServerID, DKGShare]]
    """shares[i][j] = [s_i]_j, dealt by S_i to S_j."""


@dataclass(frozen=True, slots=True, kw_only=True)
class RegisterRun:
    """Register (Sec. IV-B) on all N servers."""

    requests: dict[ServerID, TOPRFRequest]
    responses: dict[ServerID, TOPRFResponse]
    k_u: bytes
    """K_u, which U drops once step 2 is sent."""
    key_message: RegisterKeyMessage


@dataclass(frozen=True, slots=True, kw_only=True)
class LoginRun:
    """Login (Sec. IV-C) on t servers."""

    requests: dict[ServerID, TOPRFRequest]
    responses: dict[ServerID, TOPRFResponse]
    """L1, each carrying pk_u and sigma."""
    k_u: bytes
    user_pk: bytes
    """pk_u as every contacted server returned it."""
    proofs: dict[ServerID, LoginProof]
    """L2: sig_u over each server's own sid, all accepted in L3."""


@dataclass(frozen=True, slots=True, kw_only=True)
class OutsourceRun:
    """Outsource (Sec. IV-D) to one server."""

    server_id: ServerID
    request: OutsourceRequest


@dataclass(frozen=True, slots=True, kw_only=True)
class RetrieveRun:
    """Retrieve (Sec. IV-E) from every server."""

    request: RetrieveRequest
    scans: dict[ServerID, RetrieveScan]
    """R2 at each S_i, with its response L_i."""
    opened: tuple[OpenedItem, ...]
    """R3, one entry per distinct returned item."""

    @property
    def documents(self) -> list[bytes]:
        """Every recovered d, ordered by item id."""
        return [o.data for o in self.opened if o.data is not None]


def dkg(servers: Mapping[ServerID, QPASEServer]) -> DKGRun:
    """The DKG (Definition 12): Genshare at every S_i, then Genkey at every S_j over the shares addressed to it."""
    dealt = {i: server.dkg_genshare() for i, server in servers.items()}
    for j, server in servers.items():
        server.dkg_genkey([dealt[i][j] for i in servers])
    return DKGRun(shares=dealt)


def setup_servers(pp: PublicParams, capacity: int = 1000) -> dict[ServerID, QPASEServer]:
    """S_1, ..., S_N with M = capacity, keyed by the DKG."""
    servers = {i: QPASEServer(pp, i, capacity) for i in range(1, pp.N + 1)}
    dkg(servers)
    return servers


def register(user: QPASEUser, servers: Mapping[ServerID, QPASEServer]) -> RegisterRun:
    """Steps 1-3 with every server: duplicate check, TOPRF, then pk_u and sigma stored everywhere."""
    for server in servers.values():
        server.register_user(user.user_id)
    requests = user.toprf_request(sorted(servers))
    responses = {i: servers[i].toprf_evaluate(request) for i, request in requests.items()}
    k_u = user.toprf_finalize(list(responses.values()))
    key_message = user.register_keygen(k_u)
    for server in servers.values():
        server.register_store_key(key_message)
    return RegisterRun(requests=requests, responses=responses, k_u=k_u, key_message=key_message)


def login(user: QPASEUser, servers: Mapping[ServerID, QPASEServer], server_ids: Sequence[ServerID]) -> LoginRun:
    """L1 with the contacted servers, which must agree on pk_u; then L2 and L3 with each one's own sid.

    Raises ValueError for an unusable subset before any server is contacted, and ProtocolAbort
    when a server refuses L1, the password is wrong (L2), or a server rejects sig_u (L3).
    """
    requests = user.toprf_request(server_ids)
    responses = {i: servers[i].toprf_evaluate(request) for i, request in requests.items()}
    user_pks = {response.user_pk for response in responses.values()}
    if len(user_pks) != 1 or None in user_pks:
        raise ProtocolAbort("the contacted servers do not return one pk_u")
    (user_pk,) = user_pks
    k_u = user.toprf_finalize(list(responses.values()))
    proofs = {}
    for i in requests:
        proofs[i] = user.login_verify(k_u, user_pk, servers[i].new_session(user.user_id))
        if not servers[i].login_verify(proofs[i]):
            raise ProtocolAbort(f"S_{i} rejected sig_u")
    return LoginRun(requests=requests, responses=responses, k_u=k_u, user_pk=user_pk, proofs=proofs)


def outsource(user: QPASEUser, server: QPASEServer, keyword: Keyword, data: bytes, item_id: int) -> OutsourceRun:
    """O1 at U, O2 at the chosen server, which must accept sig_Ct."""
    request = user.outsource(keyword, data, item_id)
    if not server.outsource_store(request):
        raise ProtocolAbort(f"S_{server.server_id} rejected sig_Ct")
    return OutsourceRun(server_id=server.server_id, request=request)


def retrieve(user: QPASEUser, servers: Mapping[ServerID, QPASEServer], keyword: Keyword) -> RetrieveRun:
    """R1 to every server, R2 on each, R3 over all returned lists."""
    request = user.retrieve_request([keyword])
    scans = {i: server.retrieve_scan(request) for i, server in servers.items()}
    opened = user.retrieve_open([keyword], [scan.response for scan in scans.values()])
    return RetrieveRun(request=request, scans=scans, opened=tuple(opened))
