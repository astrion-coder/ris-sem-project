# Unit U7: notebook 05, our own computation and communication costs

Read `.audit/briefs/common.md` first, then `/home/iman/ris-sem-project/.claude/skills/benchmark-checklist/SKILL.md`
and `/home/iman/ris-sem-project/.claude/skills/principle-explain-the-number/SKILL.md` in full: every number this
notebook prints follows them. Paper context: Sec. VI and Tables III-IV report the authors' C++/NTL numbers at
PARAM II with N = t = 2 and 100 KB files. We do not reproduce or quote those numbers; we report our own.

## Files you own

- `notebooks/05_costs.ipynb` (new; generate with nbformat from a script in your scratchpad, run with
  `.venv/bin/python scripts/run_notebooks.py notebooks/05_costs.ipynb`)
- Not README.md: report each README-worthy number with its cell number; the lead adds the rows.

Do not edit anything under `src/`. If a measurement needs something `src/` lacks, report it.

## Setup of the measurement

- PARAM I (PARAM II is unsafe, see `params.py`), N = 3, t = 2, mu large enough for every repetition.
- Pin the kernel process to one performance core at the top of the notebook with `os.sched_setaffinity(0, {2})`
  and print the affinity and `os.getloadavg()` so the reader sees the conditions. (CPU: i5-13500, 6 P-cores at
  ids 0-11 with hyperthreads, 8 E-cores; U1 measured a_x 0.46 s on a P-core vs 0.73 s on an E-core.)
- Each timed item: one warmup, then at least 5 runs; print median and min-max range with `time.perf_counter`.
- Every timed run must also check its result (questions 4 and 7 of the checklist): e.g. login returns the registered
  pk_u, retrieve returns exactly the expected plaintexts. Count and print failures (expected 0).

## What to measure

1. Building blocks: `BPPRF.a_x` (one PRF chain), `Ring.mul` for (ell, n) x (n,), ML-DSA-44 sign and verify,
   AES-256-GCM encrypt and decrypt of a 100 KB document, TOPRF blind / server evaluate / combine.
2. Per phase, split by party (U and one S_i): Register, Login, Outsource of a 100 KB document, Retrieve over a
   server holding 10 items of which 2 match the query, and one server key update round (all N servers).
   Use the party methods directly for the split, the same order `protocol.py` uses.
3. Explain the number: for each phase, print the number of PRF chains it runs (count them from the code path
   and state the count's source in a markdown cell) times the measured a_x median, next to the measured phase
   time, and the share of the phase spent in PRF chains. Name the limiter in one sentence per phase.
4. Communication: bytes per message for every message of every phase (from the message dataclasses: sum of the
   lengths of their bytes fields), and the total per phase in each direction. These are exact, not timed.

## Report

Notebook runtime, the per-phase table (median, range, chain count, share), the communication table, and the
README rows (claim, value, cell) with `~<number> <unit>` for timings and exact values for byte counts.

## API notes (lead)

- Key update: `protocol.key_update(servers) -> KeyUpdateRun`; per server `key_update_shares()`,
  `key_update_check(shares)`, `key_update_apply(shares)`. `protocol.setup_servers` links the servers (signing keys,
  channel keys); servers built by hand cannot run the key update.
- Message sizes: `ris_sem_project.display.payload_size(message)` sums the bytes/str fields of a message dataclass;
  use it for the communication tables. `display.table` prints fixed-width tables.
- Notebooks 01-04 and 06 exist; read 02-04 to reuse their call order. Use a fresh mu (e.g. 1000) because L1 counts
  every login attempt, successful or not, until a key update.
- The lead keeps the machine otherwise idle while you run; still print `os.getloadavg()` before and after.
