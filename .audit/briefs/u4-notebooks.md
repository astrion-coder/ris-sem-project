# Unit U4: demonstration notebooks 01-03 and README

Read `.audit/briefs/common.md` first. Read CLAUDE.md (notebook rules and the README numeric-claim rule),
`docs/implementation-plan.md` (Notebooks section), and the whole package under `src/ris_sem_project/`
(params, primitives, index, parties, protocol). Use the package as it is; if something a notebook needs is
missing, add a small display helper (below) or report it, never implement protocol or primitive logic in a
notebook.

## Files you own

- `src/ris_sem_project/display.py` (new): presentation helpers only, e.g. `peek(data: bytes, width=8) -> str`
  giving `"3fa1…9c02 (1792 B)"`, a bit-string summary, a fixed-width table printer for lists of rows.
- `notebooks/01_preliminaries.ipynb`, `notebooks/02_register_login.ipynb`, `notebooks/03_outsource_retrieve.ipynb`
- `README.md`

Create notebooks with `nbformat` from a throwaway generator script under your scratchpad or /tmp (not in the
repo), then execute them only with the lead's runner: `.venv/bin/python scripts/run_notebooks.py <paths>`.
Never edit `scripts/`. Notebook kernel is the repo's `.venv` (kernelspec `python3`).

## Notebook rules

- First code cell imports from `ris_sem_project` only (plus stdlib). No new crypto, protocol, or
  primitive code in any cell. Orchestration (calling party methods in protocol order, building documents,
  printing) is fine; that is the point of the notebooks.
- Every protocol step gets a markdown cell first naming the paper step (e.g. "R2 (Sec. IV-E): S_i verifies
  sig_dsk ...") and the formula, then a code cell that runs it and prints what crossed the wire and what each
  party computed, with sizes in bytes and short hex peeks. Show who sees what.
- Each notebook ends with assertion cells that make the run fail if the demonstrated property is false
  (e.g. `assert retrieved == expected`). A notebook that runs green must mean the property held.
- Cell numbering for README: cell k = the k-th code cell = execution count [k] after a fresh Run All.

## 01_preliminaries (Sec. II)

R_q product exactness spot check, gadget G and G^{-1} identity, BP PRF a_x and F_k(x) (deterministic, bit
count ell*n), robust extractor hint/extract with a small even perturbation, DKG shares for N = 3, t = 2 and
which subsets have integer Lagrange coefficients, one TOPRF run showing F = a_x K + 2e'' noise size, lattice
HKDF and PRF output sizes. Time the BP PRF chain with `time.perf_counter` over at least 5 runs and print the
median (a README claim).

## 02_register_login (Sec. IV-A..C, Fig. 5)

pp for PARAM I with N = 3, t = 2 and a small mu. DKG messages. Register "alice" with a real password: show
the TOPRF request/response sizes per server, K_u peek, hint size, pk_u, each server's stored record. Login
with {1,2}, then {2,3}: identical K_u and pk_u. {1,3} refused (non-integer Lagrange). Wrong password: L2
mismatch and mu_u rising on each contacted server. mu limit reached: L1 refused. Repeat the correct login
K times (K >= 10) and print how many gave byte-identical K_u (README claim).

## 03_outsource_retrieve (Sec. IV-D..E, Fig. 6): the run's done predicate

This notebook is what the user reads to see searchable encryption work end to end. Make it complete and
readable.
- Setup N = 3, t = 2, DKG, register and log in "alice" with `protocol` helpers (brief recap output).
- A real corpus: at least 6 short realistic documents a person would keep in cloud storage (for example
  lab results, an invoice, meeting notes, a travel booking), each filed under one keyword, with at least two
  documents sharing a keyword. Outsource them to different servers ("arbitrary S_i").
- O1 for one document shown in full: dsk peek, rho, v peek, C size, sig_C size, Ct size, sig_Ct, the
  `OutsourceRequest` sizes. O2: the server's signature check and what it stores. Then the remaining documents
  in a table (item id, keyword, server, |Ct|, |C|).
- What each server holds: a table per server of opaque (item id, |Ct|, |C|, Ct peek), and a cell showing the
  server cannot read d (only Ct and C, no key).
- R1 for a real query keyword that matches 2+ documents: the dsk peek, sig_dsk size, the request sent to
  every S_i.
- R2 on every server, one table per server with one row per stored item: Dec result, rho, v peek,
  Ver(pk_u, (rho, v, C), sig_C), v == PRF(dsk, rho) with the recomputed v peek, outcome. Then L_i.
- R3: the user's re-check per returned item, decryption of C, and the recovered plaintext printed in full.
  Assert recovered documents equal the originals filed under that keyword, and nothing else.
- A second query for a keyword no document has: every scan row is DECRYPT_FAILED, nothing returned.
- A tampered Ct on one server: shown being rejected by the check and not returned.
- Print a final summary line per query (keyword, matched item ids, servers that returned them).

## README.md

Replace the empty README with: what the project is (QPASE paper, faithful implementation), the module map,
how to run tests (`.venv/bin/python -m unittest discover -s tests -v`) and notebooks
(`.venv/bin/python scripts/run_notebooks.py`), the deviations from the printed paper (point to
`docs/implementation-plan.md` Part 2 and list them in one line each), and a `## Numeric claims` section with
the table `| Claim | Value | Notebook | Cell |`. Every number the README states anywhere must be a row there,
and the Value must appear verbatim in that cell's output. Verify with
`.venv/bin/python scripts/check_readme_claims.py` (must print N/N). Keep claims to what the notebooks print;
do not quote the paper's own timing tables as ours.

## Done when

`.venv/bin/python scripts/run_notebooks.py` prints `ok` for all three notebooks, the unit tests are green,
and `check_readme_claims.py` passes. Report each notebook's runtime and the claims table.

## Addenda from the lead after U3 (read before starting)

- Import concrete parties from their modules: `from ris_sem_project.parties.qpase_user import QPASEUser`,
  `from ris_sem_project.parties.qpase_server import QPASEServer`. `parties/__init__` exports only the abstract
  layer and the message types.
- Notebook 02's DKG: build `QPASEServer(pp, i)` for i in 1..N and call `protocol.dkg(servers)`; its `DKGRun.shares[i][j]`
  holds every [s_i]_j for display. Elsewhere `protocol.setup_servers(pp)` does both.
- Useful U3 API: `protocol.register/login/outsource/retrieve` return run records (`RegisterRun`, `LoginRun`,
  `OutsourceRun`, `RetrieveRun` with `.scans[i].items` = per-item `ItemScan`, `.opened`, `.documents`);
  `QPASEUser.search_key(w)` returns dsk; `index.scan_item` / `ScanOutcome`; `QPASEServer.storage[user_id]` and
  `.users[user_id]` are the server's state; `QPASEServer.key` is `ServerKey(k_i, pk_i)`.
- Do not edit any file under `src/ris_sem_project/` except `display.py`. Another worker is changing
  `protocol.py` and `parties/qpase_server.py` in a separate worktree at the same time (server key update);
  notebooks 01-03 must not depend on key update.
- Cost: each lattice PRF evaluation is about 0.5 s, so a login is about 2.4 s and a retrieve with 2 matches about
  1.9 s (U3's smoke run, 1 run each). Notebook 03 should still finish in a few minutes.
- The README's deviations and caveats list must also cover, one line each: PARAM II's ring Z_q[X]/(X^595+1) has
  the root X = -1, which lets one server test password guesses offline from a single blinded request (shown by a
  sketch, not in a notebook, so state it without a number), so everything runs on PARAM I; sigma read as the
  standard deviation (Definition 3's text); the extractor hint stored at Register and returned at Login
  (decision 4); Outsource and Retrieve authorized by sig_Ct and sig_dsk, not by a passed L3, because Retrieve
  reaches all N servers and Login only t; the Gaussian sampler and extractor are not constant-time (demo code).
- Leave a `## Server key update` placeholder line in the README module map; the lead fills it in later.

## Resume addenda (lead, second session)

- A previous U4 worker was stopped mid-task. It left only `src/ris_sem_project/display.py` (uncommitted). Review it
  against this brief; keep what is right, change what is not. Its notebook generator was lost; write a new one
  outside the repo (your scratchpad), not in the repo.
- Scope change by the user: multi-keyword search (Sec. IV-G) is NOT implemented. Notebook 03 is single-keyword only
  (ignore the plan's "single + multi-keyword search"). The README's deviations and scope list says, in one line, that
  Sec. IV-G is a paper extension left out of this implementation.
- README claim values that change between runs (timings, observed noise maxima) are written `~<number> <unit>`, for
  example `~0.5 s`; `check_readme_claims.py` accepts the cell's printed value within a factor of 2. Byte sizes,
  counts and other deterministic values stay exact.
- Two other workers run at the same time (server key update in a worktree, a PARAM II attack notebook in this
  checkout), so timings you see are noisier than usual; the lead reruns every notebook at the end.
- The PARAM II line in the README deviations list points to `notebooks/06_param_ii_offline_guessing.ipynb` (another
  worker writes it); do not create that notebook and do not add its claim rows.
