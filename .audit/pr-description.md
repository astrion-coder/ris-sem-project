feat(qpase): implement QPASE with a notebook for every phase

## Why

The repository had only abstract party classes. This branch implements QPASE as `docs/implementation-plan.md` specifies, so you can run every phase on a laptop and see each message the user and the servers exchange.

## What changed

- `src/ris_sem_project/` gains the lattice layer (ring arithmetic, BP PRF, robust extractor, DKG, TOPRF, lattice HKDF), ML-DSA-44 and AES-256-GCM wrappers, the concrete `QPASEUser` and `QPASEServer` with the server key update, and `protocol.py`, which runs each phase and records its messages.
- Notebooks 01 to 06 show each phase. Notebook 03 stores real documents on three servers, runs a keyword search, and prints every R1, R2 and R3 step down to the recovered plaintexts.
- `scripts/run_notebooks.py` reruns the notebooks, and `scripts/check_readme_claims.py` checks each README number against the cell that prints it.

## Scope

- Covers Setup, the DKG, Register, Login, Outsource, single-keyword Retrieve and the server key update, on PARAM I.
- Leaves out multi-keyword search (Sec. IV-G) and the security-game Challenger.

## Tradeoffs

- PARAM II stays in `params.py`, but no demo uses it. Run in the scheme text's ring `Z_q[X]/(X^595 + 1)`, it has the root X = -1, and notebook 06 shows one server testing password guesses offline against a single login request. The paper's estimate for n = 595 likely assumes plain LWE, so this is a flaw of our reading of the parameters, not a proven flaw of the paper.
- The key update's linear commitments reveal every update share to an eavesdropper. A hiding commitment needs randomness that the paper does not give, so the README lists this as a known gap.

## Blast Radius

The branch mostly adds new modules. In existing files it adds three `hint` fields to the wire messages in `parties/types.py` and fixes the `server_pk` docstring there, rewords one docstring in `parties/server.py`, adds ipykernel and nbclient as dev dependencies, and stops tracking `__pycache__`.

## Verification

- `.venv/bin/python -m unittest discover -s tests` passes 143 tests.
- `.venv/bin/python scripts/run_notebooks.py` runs all six notebooks, and each ends in passing assertion cells.
- `.venv/bin/python scripts/check_readme_claims.py` finds all 54 README claims in their cells.

The decision trail is `.audit/qpase-implementation.tsv`.

🤖 Generated with [Claude Code](https://claude.com/claude-code)
