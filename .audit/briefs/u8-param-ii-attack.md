# Unit U8: PARAM II offline password test via the root X = -1 (finding, notebook 06)

Read `.audit/briefs/common.md` first. Read `src/ris_sem_project/params.py` (the `PARAM_II` docstring states the
finding), `primitives/toprf.py`, `primitives/bp_prf.py`, `parties/qpase_user.py`, and the abstract
`parties/adversary.py`.

## The finding (verified by the lead once, 5 guesses, before its scratch script was lost)

PARAM II uses R_q = Z_q[X]/(X^595 + 1) (Table II's n = 595, plan decision 1). 595 is odd, so X = -1 is a root of
X^595 + 1 and phi(a) = a(-1) = sum_i (-1)^i a_i mod q is a ring homomorphism R_q -> Z_q. A semi-honest server that
receives one blinded TOPRF request b = a r + a_x + 2e (Fig. 2) computes, for a password guess x',
c_j = phi(b_j) - phi(a_x'_j) = phi(a_j) phi(r) + 2 phi(e_j) when x' is the real password. phi(r) and phi(e_j) are
sums of 595 signed Gaussians, about sigma sqrt(n) ~ 78 in size. So the server tries every rho in [-R, R] and checks
whether max_j |centered(c_j - rho phi(a_j))| is small. The right guess gives a residual of a few hundred and
recovers phi(r) = rho; a wrong guess leaves residuals near q/4 ~ 6.7e7. The lead's run: true password residual 350,
wrong guesses about 1e8, and PARAM I (X^512 + 1, which has no root because 1024 does not divide q - 1) matched
nothing. This breaks the offline-guessing resistance (attack 1 in Fig. 3) for PARAM II only.

## Files you own

- `src/ris_sem_project/root_attack.py` (new): the attack as plain functions over what a server sees. Suggested shape:
  `evaluate_at_minus_one(ring, a) -> np.ndarray` (phi on the last axis), a frozen `GuessResult(password, residual,
  phi_r: int | None, matched: bool)`, and `offline_password_test(pp, request: TOPRFRequest, guesses, radius=1500,
  threshold=...) -> list[GuessResult]`. Choose the threshold from the noise math (state it in the docstring), not by
  tuning on a run. Docstring: which paper claim it breaks and why PARAM I is not affected.
- `tests/test_root_attack.py` (new): with a real `QPASEUser(...).toprf_request(...)` at PARAM II, the true password is
  matched with the right phi(r) and wrong guesses are not; at PARAM I nothing is matched. Use at least 4 wrong guesses.
- `notebooks/06_param_ii_offline_guessing.ipynb` (new): explain the root (with the one-line algebra), set up
  PARAM II servers and a user with a real password, capture the blinded request the way a server receives it, run
  the test over a dictionary of at least 20 common passwords containing the real one, print the residual table and
  the recovered phi(r) next to the true phi(r) (the notebook may read the user's r only to show it matches), then
  the PARAM I control. End with assertion cells. Generate it with nbformat from a script in your scratchpad and run it
  with `.venv/bin/python scripts/run_notebooks.py notebooks/06_param_ii_offline_guessing.ipynb`.

Do not edit any other file, README.md included. Two other workers are active: one writes notebooks 01-03 and the
README in this checkout, one works in a separate worktree. Report every number notebook 06 prints that belongs in
the README with its cell number, using `~<number> <unit>` for values that change between runs.
