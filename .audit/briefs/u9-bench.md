# Unit U9: move notebook 05's measurement code into src/

Read `.audit/briefs/common.md` first, then CLAUDE.md. A reviewer flagged that `notebooks/05_costs.ipynb` breaks
CLAUDE.md's rule that notebooks only call `src/` and hold no new implementation: its cell 2 is a ~136-line
measurement framework (`Clock`, `Measured`, `measure`), it monkey-patches `BPPRF.a_x` inside the notebook to count
PRF chains, cell 4 defines a schoolbook product reference, and cell 1 hard-codes CPU 2 and `/sys` paths, so it
fails on a machine with fewer than 3 CPUs.

## Files you own

- `src/ris_sem_project/bench.py` (new): the measurement helpers notebook 05 needs, as small public functions and
  frozen dataclasses: pinning to one CPU when it exists (return what it did, never fail when the CPU is missing or
  `/sys` is unreadable), reading CPU clock and load, timing a callable with warmup and N runs returning median and
  range, counting failures from a check callable, and a context manager that counts `BPPRF.a_x` calls per party
  (the one place that wraps `a_x`, restored on exit even after an exception). Put the schoolbook negacyclic product
  reference here too, or reuse an existing src function if one fits. Docstrings say each is measurement code, not
  protocol code.
- `tests/test_bench.py` (new): the timer returns run counts and an ordered range, the chain counter counts a known
  number of `a_x` calls and restores the original method even when the block raises, pinning to a CPU that does not
  exist reports that it skipped and does not raise.
- `notebooks/05_costs.ipynb`: regenerate it from a copy of the lead's generator
  `/tmp/claude-1000/-home-iman-ris-sem-project/557db587-1f2e-4ba6-9c37-4eb6bfdbb982/scratchpad/make_05.py`
  (copy it into your own scratchpad and edit the copy) so every cell imports these helpers from
  `ris_sem_project.bench` and defines no classes or measurement functions of its own. Run it with
  `.venv/bin/python scripts/run_notebooks.py notebooks/05_costs.ipynb`.

## Constraints

- Keep exactly 12 code cells in the same order, and keep every printed line that README.md cites (the
  `notebooks/05_costs.ipynb` rows of its `## Numeric claims` table) with the same label text, so the README rows
  stay valid. After your run, `.venv/bin/python scripts/check_readme_claims.py` must still pass every row.
- Pin to CPU 2 when it exists, as now, and print what happened.
- Do not edit README.md, other notebooks, or other src files. The machine is otherwise idle while you run.
- The unit suite stays green: `.venv/bin/python -m unittest discover -s tests`.
