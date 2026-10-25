# Unit U5: server key update (Sec. IV-F, Lemma 3) and notebook 04

Read `.audit/briefs/common.md` first. Paper: Sec. IV-F steps 1-5 and Lemma 3 (extract the text with
pdftotext). Plan: Part 2 decision 6. Read the merged package (`params.py`, `primitives/`, `index.py`,
`parties/`, `protocol.py`) and use it as it is; report anything wrong instead of editing files you do not own.

## Files you own

- `src/ris_sem_project/primitives/linear_hash.py` (new), `tests/test_linear_hash.py` (new)
- `src/ris_sem_project/parties/qpase_server.py` (add the key-update methods and what they need)
- `src/ris_sem_project/parties/server.py` (docstring of `key_update_apply` only, to match decision 6)
- `src/ris_sem_project/protocol.py` (add `key_update(servers) -> KeyUpdateRun`, extend `setup_servers`)
- `tests/test_key_update.py` (new)
- `notebooks/04_server_key_update.ipynb` (new; generate with nbformat from a script outside the repo, run it with
  the worktree command at the end of this brief)
- Not `README.md`: another worker owns it while you run. Report every number notebook 04 prints that belongs in
  the README (value, cell number) and the one-line module-map entry; the lead adds them.

## Decisions already made (keep them)

- H (decision 6): H(x) = A_H x mod q for x in R_q read as its n coefficients, A_H in Z_q^{n x n} expanded
  deterministically from SHAKE256(b"QPASE/H") by rejection sampling (public, like a seed-expanded matrix).
  Linear, so H(F(i)) = sum_k i^k H(alpha_k) holds. Keep the product exact (limb split; values < 2^63).
- Update polynomial: S_j samples [F]_j(X) = sum_{k=1}^{t-1} alpha_k X^k, alpha_k uniform in R_q, constant 0.
  Every server participates. S_i sets k_i' = k_i + sum_j [F]_j(i) mod q (decision 6: the printed lambda_{i,j}
  is dropped; a sum of zero-constant degree t-1 polynomials keeps K = sum lambda_i k_i' unchanged, Lemma 3).
- Server signing keys: each server gets an ML-DSA-44 key pair at construction; `setup_servers` hands every
  server the others' verification keys. sig_j = Sign(sk_j, pack(int_bytes(j), int_bytes(omega), *h, E(i, F_ji))).
- E(i, .): the paper assumes secure server-to-server channels (Sec. III-A). Model it as AES-256-GCM under a
  pairwise 32-byte key per server pair that `setup_servers` generates with os.urandom and gives to both ends.
  Say so in the docstring; it stands in for the channel, it is not a scheme contribution.
- Step 4 checks per received share: sender's signature, epoch == current epoch, decrypts, and
  H(F_ji) == sum_k i^k h_k. Any failure raises `ProtocolAbort` and applies nothing (all-or-nothing).
- Step 5: pk_i' = a k_i' + 2e_i via `toprf.server_public_key`, every mu_u reset to 0, epoch += 1. The users'
  stored records and outsourced items are untouched.
- Every share must be addressed to the receiver, one per sender, all N senders present.

## Tests (`tests/test_key_update.py`, PARAM I, N = 3, t = 2)

- After an update: every k_i and pk_i changed, epoch is 1, mu_u is 0 on every server.
- A user registered before the update logs in afterwards with {1,2} and {2,3} and gets the same pk_u, and a
  document outsourced before the update is still retrieved byte-equal after it (Lemma 3).
- A share with a corrupted commitment, a corrupted encrypted share, a bad signature, or a stale epoch is
  rejected and leaves that server's k_i, pk_i and epoch unchanged.
- `test_linear_hash.py`: linearity H(a + b) = H(a) + H(b), H(c a) = c H(a) for integer c, determinism of A_H,
  and an exactness check of the product against Python big ints at n = 512.

## Notebook 04

Before/after: pk_i peeks per server, the broadcast message sizes, the commitment check per share printed per
(sender, receiver), mu reset, then login gives the same K_u peek as before and a pre-update document is
retrieved. End with assertion cells. Report the numbers it prints for the lead to put in the README.

## Where you work (runs in parallel with the notebooks unit)

You work in your own git worktree, `/home/iman/ris-sem-project-u5` (the lead creates it), not in the main
checkout, so the other worker's notebooks never import your half-edited files. There is no `.venv` in the
worktree and you must not create one. Run everything from the worktree root with the main checkout's
interpreter and the worktree's sources first on the path:

    PYTHONPATH=/home/iman/ris-sem-project-u5/src /home/iman/ris-sem-project/.venv/bin/python -m unittest discover -s tests -v
    PYTHONPATH=/home/iman/ris-sem-project-u5/src /home/iman/ris-sem-project/.venv/bin/python scripts/run_notebooks.py notebooks/04_server_key_update.ipynb

Check once that `ris_sem_project.__file__` resolves inside the worktree before trusting a run. Write only inside
the worktree. Do not commit; the lead commits on the worktree's branch.

## Resume addenda (lead, second session)

- A previous U5 worker was stopped mid-task. In the worktree it left, uncommitted: `primitives/linear_hash.py`,
  `tests/test_linear_hash.py`, and about 164 added lines in `parties/qpase_server.py`. It had not yet written
  `tests/test_key_update.py`, the `protocol.py` changes, the `server.py` docstring fix, or notebook 04. Review what
  it left against this brief, keep what is right, fix what is not, and finish the unit.
- The worktree has no `notebooks/` directory yet; create it there.
- README claim values that change between runs are written `~<number> <unit>`; report yours that way.
