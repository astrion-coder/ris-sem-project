# Unit U3: concrete user and server, the searchable index, and the protocol runner

Read `.audit/briefs/common.md` first. Paper refs: Sec. IV-A..E, Fig. 5-6. Plan refs: Part 2 decisions 3-4
and 7, Part 3 `parties/`. U1 (lattice) and U2 (signature, symmetric, encoding) are merged; read their modules
under `src/ris_sem_project/primitives/` and `src/ris_sem_project/params.py` and use them as they are. If one
of them is wrong or missing something you need, stop and report it instead of editing it.

## Files you own

- `src/ris_sem_project/parties/types.py` (extend only, as listed below)
- `src/ris_sem_project/parties/__init__.py` (add exports)
- `src/ris_sem_project/index.py` (new)
- `src/ris_sem_project/parties/qpase_user.py` (new), `src/ris_sem_project/parties/qpase_server.py` (new)
- `src/ris_sem_project/protocol.py` (new)
- `tests/test_protocol.py` (new)

Do not change the abstract classes in `parties/user.py`, `parties/server.py`, `parties/base.py` or
`parties/adversary.py`, except that you may fix a docstring that your implementation proves wrong (report it).

## types.py extension (plan decision 4)

- `UserRecord.hint: bytes | None = None`: the extractor hint sigma = S(F_reg), packed ell*n bits, stored at Register step 3.
- `RegisterKeyMessage.hint: bytes`: U sends sigma with pk_u in Register step 2.
- `TOPRFResponse.hint: bytes | None = None`: S_i returns sigma with pk_u in Login step L1 (None during Register).
Docstrings say these are the plan's decision-4 deviation from Fig. 2.

## Fixed encodings (one source of truth, all through `primitives.encoding`)

Domain-separated derivations from K_u, with `h = Hkdf(lattice.prf, K_u)`:
- dsk = `h.derive(b"QPASE/dsk/" + w.encode())` for keyword w.
- AES key for C: `aes_key(h.derive(b"QPASE/enc"))`. Dilithium seed: `aes_key(h.derive(b"QPASE/sig"))` (32 bytes)
  then `keypair_from_seed` gives (pk_u, sk_u) = Gen(1^kappa, K_u).
- Password bits x = `encode_input(psw.encode(), L)` (plan: first L bits of SHA3-256(psw)).
- v = `prf(lattice.prf, dsk, b"QPASE/v/" + int_bytes(rho))`, rho <- Z_q via `uniform_zq`.
Signed and encrypted tuples:
- sig_C = Sign(sk_u, pack(int_bytes(rho), v, C)).
- Ct = Enc(aes_key(dsk), pack(int_bytes(rho), v, sig_C)).
- sig_Ct = Sign(sk_u, pack(Ct, C, int_bytes(i))).
- sig_u = Sign(sk_u', pack(ID_u.encode(), sid)).
- sig_dsk = Sign(sk_u, pack(*search_keys)).

## `index.py`: the per-item search check, shared by R2 (server) and R3 (user)

Both sides run the same check, so it lives once, as pure functions:
- `build_item(lattice, sk_u, k_enc, dsk, data, item_id) -> StoredItem`: Outsource step O1 minus sig_Ct
  (samples rho, computes v, C, sig_C, Ct).
- `ScanOutcome` enum: `DECRYPT_FAILED`, `MALFORMED`, `SIGNATURE_INVALID`, `PRF_MISMATCH`, `MATCH`.
- `ItemScan` frozen dataclass: `item_id`, `outcome`, `rho: int | None`, `v: bytes | None`,
  `v_recomputed: bytes | None`, `sig_c: bytes | None`. Fields are None exactly when the step that produces
  them did not run (decrypt failed => all None).
- `scan_item(lattice, pk_u, dsk, item) -> ItemScan`: (rho, v, sig_C) = Dec(dsk, Ct); Ver(pk_u, (rho, v, C), sig_C);
  v == PRF(dsk, rho). Stop at the first failing step (do not compute the PRF when the signature fails).

## `QPASEUser(User)` in `qpase_user.py`

Model the user's lifecycle explicitly (a small state object per phase, not scattered booleans):
- TOPRF in flight: holds r and the contacted ids between `toprf_request` and `toprf_finalize`.
- After `toprf_finalize` at Register: holds the freshly computed hint until `register_keygen` sends it.
  Register step 4: after `register_keygen` the user keeps only (ID_u, psw_u); no session survives Register.
- Logged in: after a successful `login_verify`, holds K_u, the Hkdf, (pk_u, sk_u) and the AES key for C.
  `outsource`, `retrieve_request`, `retrieve_finalize` raise `ProtocolAbort` when not logged in.
Methods (abstract contract in `parties/user.py`):
- `encode_password` returns the packed L bits.
- `toprf_request(server_ids)`: one blinded b (Fig. 2: the same x* to every contacted server), one
  `TOPRFRequest` per id.
- `toprf_finalize(responses)`: parse each evaluation/pk with `Ring.from_bytes` (boundary), `toprf.combine`
  over the responding ids, then Register (no hint in responses) -> compute hint; Login (hint present) ->
  all hints must be equal, use it. Returns K_u.
- `register_keygen(k_u)`: derive (pk_u, sk_u), return `RegisterKeyMessage(user_id, user_pk, hint)`, forget K_u.
- `login_verify(k_u, stored_pk, session_id)`: derive (pk_u', sk_u') from K_u (cache per K_u so t servers do
  not re-derive), raise `ProtocolAbort` if pk_u' != stored_pk (wrong password: "U re-inputs the password"),
  else sign (ID_u, sid) and enter the logged-in state.
- `outsource(keyword, data, item_id)`: `build_item` then sig_Ct, return `OutsourceRequest`.
- `retrieve_request(keywords)`: one dsk per keyword, sig_dsk over all of them.
- `retrieve_open(keywords, responses) -> list[OpenedItem]` (extra public method; `OpenedItem` frozen dataclass
  in `qpase_user.py` with `item_id`, `server_ids` that returned it, the user's `ItemScan`, `data: bytes | None`):
  R3. De-duplicate results by item_id across servers, `scan_item` with the user's own dsk, decrypt C with the
  AES key only on MATCH.
- `retrieve_finalize(keywords, responses)`: the `data` of every MATCH from `retrieve_open`, ordered by item_id.
For this unit, single-keyword queries are the contract (`len(keywords) == 1`, else raise `ValueError`).
Multi-keyword search is a later unit.

## `QPASEServer(Server)` in `qpase_server.py`

- `__init__(pp, server_id, capacity=1000)`: parse pp once via `Lattice.from_pp`. capacity is the paper's M
  storage slots per user.
- DKG: `dkg_genshare` returns a `DKGShare` for every j in 1..N (including itself); `dkg_genkey` checks it got
  exactly one share from each of the N senders addressed to itself, sets k_i, and computes pk_i with
  `toprf.server_public_key`.
- `register_user`: duplicate ID_u -> `ProtocolAbort`. `register_store_key`: record must exist and have no pk yet.
- `toprf_evaluate`: unknown user -> `ProtocolAbort`. If the record has no pk yet it is the Register evaluation
  (no counter). Otherwise Login L1: abort if mu_u >= mu, then mu_u += 1, and include pk_u and the hint.
- `new_session(user_id)`: fresh 32-byte sid, one outstanding per user. `login_verify(proof)`: the sid must be
  the outstanding one (consume it); Ver(pk_u, (ID_u, sid), sig_u); on failure mu_u += 1 and return False.
- `outsource_store(request)`: Ver(pk_u, (Ct, C, i), sig_Ct) else return False. Store; an existing item with the
  same i is replaced; when the user's M slots are full the oldest item is evicted.
- `retrieve_scan(request) -> RetrieveScan` (extra public method; `RetrieveScan` frozen dataclass in this module
  with `server_id`, `items: tuple[ItemScan, ...]`, `response: RetrieveResponse`): Ver(pk_u, dsk, sig_dsk) else
  `ProtocolAbort`; `scan_item` every stored item of that user; the response holds the MATCH items.
  `retrieve_search(request)` returns `retrieve_scan(request).response`.

## `protocol.py`: runs whole phases by moving messages between parties

Plain functions that the tests and the notebooks share. Each returns a frozen dataclass holding every message
it moved, so a notebook can display them without re-implementing anything:
- `setup_servers(pp, capacity=1000) -> dict[ServerID, QPASEServer]`: create S_1..S_N and run the DKG.
- `register(user, servers) -> RegisterRun`: all N servers (register_user, TOPRF, store key).
- `login(user, servers, server_ids) -> LoginRun`: the t contacted servers; all must return the same pk_u
  (else `ProtocolAbort`); L2 per server with that server's sid; L3 must accept on every contacted server.
- `outsource(user, server, keyword, data, item_id) -> OutsourceRun`.
- `retrieve(user, servers, keyword) -> RetrieveRun`: R1 to every server, R2 `retrieve_scan` on each, R3
  `retrieve_open`; holds the request, each server's `RetrieveScan`, the opened items and the documents.

## Tests (`tests/test_protocol.py`, full PARAM I, N = 3, t = 2, mu large enough for the suite)

Share one setup + registration across tests where possible (setUpClass) to keep runtime down.
- Register then login with {1,2} succeeds; login with {2,3} yields the same pk_u; login with {1,3} raises.
- Wrong password: login raises `ProtocolAbort` at L2, and each contacted server's mu_u went up.
- mu limit: with mu = 2, the third login attempt is refused at L1 by the server.
- Duplicate Register raises.
- Outsource 4 real short documents under 2 keywords to different servers. Retrieve keyword A returns exactly
  the plaintexts filed under A (byte-equal to the originals, from the servers that hold them), keyword B
  likewise, and an absent keyword returns `[]`, with every server's scan showing `DECRYPT_FAILED` for the
  other keyword's items.
- A tampered `OutsourceRequest` (flip a byte of Ct) is rejected; a `RetrieveRequest` with a bad signature
  aborts; outsource before login raises.
- A second user registered on the same servers cannot see the first user's documents with their own query.
Report the suite runtime.

## Addenda from U1's hand-back (lead, after review)

- `BPPRF` takes `L` as a fourth argument; always get it from `Lattice.from_pp(pp).prf`.
- Fix the `TOPRFResponse.server_pk` docstring in `types.py`: the pk_i sent is the unrounded a k_i + 2e_i
  (plan decision 4), not floor(a k_i)_p.
- Cost: every `prf()` call, every `Hkdf(...)` construction and every `derive` runs one 127-step `a_x`
  (about 0.46 s on a P-core, 0.73 s on an E-core, measured by U1). Keep the count minimal: one `Hkdf` per K_u,
  derive the Dilithium seed and the AES key once per session, reuse them for all t servers in Login.
- Ring helpers: `Ring.pack_bits` / `Ring.unpack_bits` (shape (ell, n), rejects bad padding) are the only bit
  packing; the hint travels as `ring.pack_bits(hint)` and comes back through `ring.unpack_bits`.
- Use PARAM I everywhere. PARAM II's ring has the root X = -1 and is unsafe (see `PARAM_II` docstring).
- Keep `tests/test_protocol.py` under about 2 minutes.
