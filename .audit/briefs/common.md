# QPASE build: contract for every worker

You implement one unit of Jiang & Wang, "QPASE" (IEEE TIFS 19, 2024) in `src/ris_sem_project/`.
The approved design is `docs/implementation-plan.md`. Read it fully. Your unit brief overrides it
only where it says so. The paper text is extractable with
`pdftotext -layout QPASE_Quantum-Resistant_Password-Authenticated_Searchable_Encryption_for_Cloud_Storage.pdf <out.txt>`
(write `<out.txt>` under your scratchpad or /tmp, never in the repo).

## Fences

- Never install anything. No `uv add`, `uv sync`, `uv run`, `pip`. `uv run` can sync the env, so do not use it.
- Run Python only as `.venv/bin/python` from the repo root `/home/iman/ris-sem-project`.
- Do not commit, stash, switch branches, or touch git state. The lead reviews and commits.
- Write only the files your unit brief lists. Never edit `.audit/`, `scripts/`, `CLAUDE.md`, `docs/`, or files another unit owns.
- Notebooks (`notebooks/*.ipynb`) only call `src/`. They hold no protocol or primitive logic.

## Code style

- Python 3.14, type hints, `from __future__` not needed. Match the existing modules in
  `src/ris_sem_project/parties/` (module docstring citing the paper section, short docstrings that
  use the paper's notation, frozen `slots=True, kw_only=True` dataclasses for values that cross a party boundary).
- Comments only for a non-obvious why. No step-narrating comments.
- Validate at boundaries (bytes from another party, `PublicParams`, user input). Trust internal types.
- Randomness: `os.urandom` / `secrets` only. No `np.random` for anything secret or public-parameter sampling.

## Tests

- stdlib `unittest`, files `tests/test_<topic>.py`. Run: `.venv/bin/python -m unittest discover -s tests -v`.
- Test behavior a caller can observe. Derive expected values from the math or a slow, obviously-correct
  reference written in the test (e.g. pure-Python schoolbook), never from the code under test.
- Keep the whole suite under about 3 minutes. Use small parameters (e.g. n = 8 or 16, L = 4..8) for
  exhaustive or reference checks, and full PARAM I only where the property needs it.

## Report back

Return: files written, the exact test command and its final summary line, any measured numbers with how
you measured them (run count), every place you departed from the plan or this brief and why, and
anything you are unsure about. Do not claim a check you did not run.
