# QPASE — paper understanding + implementation plan

## Context

The user wants to implement Jiang & Wang, "QPASE: Quantum-Resistant Password-Authenticated
Searchable Encryption for Cloud Storage" (IEEE TIFS 19, 2024) **faithfully, as the paper
specifies** (no improvements; `P14_QPASE_project.md` is NOT the plan). Abstract party classes
already exist in `src/ris_sem_project/parties/` (User, Server, Adversary, Challenger + message
dataclasses in `types.py`). This plan records what the paper says (so it stays in context), where
the paper is under-specified or internally inconsistent, and how to build it in `src/` with
demonstration notebooks in `notebooks/` (per CLAUDE.md: notebooks only call `src/`; every numeric
claim goes into README.md with notebook + cell number; no installs by Claude).

---

## Part 1 — What the paper specifies

### Setting & entities (Sec. III-A, Fig. 3)
- **User U**: holds only (ID_u, psw_u). Derives user-specific key K_u via a t-of-N lattice TOPRF,
  then Dilithium keypair (pk_u, sk_u) = Gen(1^κ, K_u) and per-keyword search key dsk = HKDF(K_u, w).
- **Servers S = {S_1..S_N}**: each holds key share k_i (from DKG), stores (ID_u, pk_u, k_i, μ_u)
  and outsourced (Ct, C, i). Semi-honest, secure channel; adversary corrupts ≤ t' < t servers.
- **Adversary** (quantum): ① offline guessing, ② online guessing, ③ chosen-keyword attacks.
  BPR model oracles: Execute, Send, Test, Reveal, Corrupt; IND-CKA oracles Challenge, Reg, LoginU,
  LoginS, OutU, OutS, RetU, RetS (Sec. III-B, Fig. 4).

### Preliminaries (Sec. II)
- Ring R_q, public a, a_0, a_1 ∈ R_q^{1×ℓ}, ℓ = ⌈log2 q⌉. Gadget G = (1,2,…,2^{ℓ−1});
  G^{-1}: R_q^{1×ℓ} → R_q^{ℓ×ℓ} (binary decomposition).
- **BP lattice PRF** (Lemma 1, [80] Banerjee–Peikert): a_x = a_{x1}·G^{-1}(a_{x2}·G^{-1}(…a_{xL})),
  F_k(x) = ⌊(p/q)·a_x·k⌉. Needs q ≫ p·σ·n·ℓ·√L.
- **TOPRF Fig. 1** ([68]/[79] Albrecht et al. style): U samples s, e; sends x* = A·s + e + a^F(x)
  to ≥ t servers. S_i samples e'_i, returns x*_{k_i} = x*·k_i + e'_i. U computes
  PK = Σ λ_i·pk_i and outputs F_K(x) = ⌊(p/q)·a^F(x)·K⌉ (i.e. Σλ_i x*_{k_i} − PK·s, then round).
- **Variant TOPRF Fig. 2 (Π_TOPRF)**: same, with even noise (b = ⌊a·r + a^F x + 2e⌉_p,
  b_{k_i} = ⌊b·k_i + 2e'_i⌉_p, vk_i = ⌊a·k_i + 2e_i⌉_p) and a **robust extractor** (Ding et al. [69],
  Def. 8): hint σ ← S(y) with σ0/σ1 signal functions; E(x,σ) = (x + σ·(q−1)/2 mod q) mod 2;
  E(x,σ)=E(y,σ) when x−y even and small. Output K_u = ⌊E(F_K(x), σ)⌉_p.
- **HKDF** (Def. 9/10): Krawczyk extract-then-expand; paper says "introduce lattice PRF [80] into
  Krawczyk's framework". dsk ← HKDF(K_u, w). PRF: K_u × {0,1}^K → {0,1}^K.
- **DKG** (Def. 11/12, Bendlin et al. [83]): Genshare samples share polynomial; Genkey
  k_j = Σ_i [s_i]_j; master K never reconstructed. Server pk_i = A·k_i + e_i (Fig. 5).
- **Signature**: CRYSTALS-Dilithium (EUF-CMA + BUFF properties). **Symmetric**: AES-256 (Grover → 128-bit).

### Protocol (Sec. IV, Figs. 5–6)
- **Setup**: pp (a, a_0, a_1, σ, q, n, μ, N, t, Enc/Dec, H, HKDF, PRF); servers run DKG.
- **Register** (secure channel): (1) U↔each S_i run Π_TOPRF → K_u; S_i rejects duplicate ID_u.
  (2) (pk_u, sk_u) ← Gen(1^κ, K_u); send pk_u to all S_i. (3) S_i stores ID_u, pk_u, k_i, μ_u=0.
  (4) U remembers only ID_u, psw_u.
- **Login**: L1 with t servers: S_i checks μ_u < μ else abort; μ_u += 1; TOPRF → K_u; S_i returns pk_u.
  L2: U derives (pk_u', sk_u'); if pk_u' ≠ pk_u re-enter password; else sig_u = Sign(sk_u', (ID_u, sid)).
  L3: S_i Ver; on failure abort and μ_u += 1.
- **Outsource** O1: ρ ← Z_q, dsk = HKDF(K_u, w), v = PRF(dsk, ρ), C = Enc(K_u, d),
  sig_C = Sign(sk_u, (ρ, v, C)), Ct = Enc(dsk, (ρ, v, sig_C)), sig_Ct = Sign(sk_u, (Ct, C, i)) →
  arbitrary S_i. O2: S_i verifies, stores (Ct, C, i) (M slots; replace if full).
- **Retrieve** R1: dsk = HKDF(K_u, w), sig_dsk = Sign(sk_u, dsk) → all S_i. R2: S_i verifies; for
  each Ct: (ρ, v, sig_C) = Dec(dsk, Ct); if Ver(pk_u, (ρ,v,C), sig_C) and v = PRF(dsk, ρ) add to L_i.
  R3: U re-checks, d = Dec(K_u, C).
- **Server key update** (IV-F): zero-constant polynomial [F] (deg t−1), shares F^i_j with
  commitments h = {H(α_k)}, signed; S_i verifies H(F^i_j) = Σ H(α_k)^{i^k}, sets
  k_i' = k_i + Σ λ_{i,j}[F]^i_j, pk_i' = A·k_i' + e_i, resets μ_u, epoch ω+1. K unchanged (Lemma 3).
- **Multi-keyword** (IV-G): v = (v_1..v_k); conjunctive (v = v'), disjunctive (|v∩v'| > 0), subset (v' ⊆ v).

### Security & evaluation (Sec. V–VI)
- Thm 2 Auth: Adv ≤ 2C'·q_s^{s'} + Adv^DLWE + Adv^{1D-SIS} + Adv^Sig + ε; Zipf (Taobao):
  |D| = 15,072,667, C' = 0.0166957, s' = 0.194179. Thm 3 IND-CKA adds Adv^HKDF.
- Params (Table II): q = 2^28 − 57; PARAM I n = 512, β = 342 (100-bit classical / 92-bit quantum);
  PARAM II n = 595, β = 478 (140 / 128-bit). Experiments used PARAM II, N = t = 2, 100 KB files.
- Table III/IV: per-operation times and per-phase compute/communication (paper's C++/NTL numbers;
  only reproduce what we measure ourselves).

---

## Part 2 — Gaps/inconsistencies in the paper that force decisions

1. **Ring vs plain LWE**: Fig. 1 uses A ∈ Z_q^{m×n} (plain LWE); Sec. II-B/IV-A/Fig. 2 use
   a ∈ R_q^{1×ℓ} (ring). PARAM II n = 595 is not a power of two (no X^n+1 cyclotomic), suggesting
   plain-LWE (Frodo-style) parameter scripts. Plain-LWE BP PRF with n=512 needs 14336×14336
   matrices × L steps — infeasible in Python. → Use **ring R_q = Z_q[X]/(X^n+1)** as in the scheme text.
2. **q = 2^28 − 57 is not NTT-friendly** (q−1 = 2·134217699). → Polynomial multiplication via
   numpy FFT with limb splitting (exact in float64), batched over the ℓ×ℓ products.
3. **TOPRF combine uses the paper's formula exactly (user decision, no Δ)**:
   F_K(x) = Σλ_i·b_{k_i} − Σλ_i·pk_i·r = a_x·K + 2e'', e'' = e·K + Σλ_i e'_i − r·Σλ_i e_i
   (Thm 1 proof; p. 4234 prints "+r", p. 4241 "−r"; algebra gives "−"). For e'' to be small:
   - λ_i must be integers → the user contacts only t-subsets whose Lagrange coefficients at 0 are
     integers (always true for {1..t}: λ_i = (−1)^{i+1}·C(t,i)); `toprf` rejects other subsets.
   - K must be small → DKG contributions are sampled from χ_σ (Def. 12 leaves the distribution
     open; small keys are what the TOPRF of [68]/[79] requires). Shares k_i still look uniform.
   - r (= s in Fig. 5) and e must be small → r, e ← χ_σ (Fig. 5 says s ← χ_σ).
4. **Reproducible K_u needs the hint from the right value**: rounding F alone flips some of the
   28·512 = 14,336 coefficients between logins (estimate, to verify in a notebook), so pk_u' ≠ pk_u.
   Ding's extractor fixes it only if σ = S(y) is computed on a previous F; Fig. 2's S(vk_i) is
   computed on a·k_i + 2e_i, an unrelated value. → **Even noise everywhere (2e, 2e'_i, 2e_i as in
   Fig. 2), unrounded messages as in Fig. 1/Fig. 5; U computes σ = S(F_reg) at Register, servers
   store it and return it with pk_u at Login; K_u = E(F_login, σ) ∈ {0,1}^{ℓn}.** Works because
   F_login − F_reg = 2(e''_login − e''_reg) is even and far below q/4. This is the one remaining
   deviation from the printed Fig. 2.
5. **DKG threshold**: Def. 11 says degree-t polynomial / "t+1 reconstruct", Login uses t servers.
   → Degree t−1 so any t of N servers suffice (matches Login and Fig. 5).
6. **Key-update commitments**: "H(F^i_j) = Σ H(α_k)^{i^k}" needs a linear/homomorphic H; a generic
   collision-resistant hash cannot satisfy it. → H(x) = A_H·x mod q (linear Ajtai/SIS hash, matches
   "H: {0,1}* → Z_q^n is a collision-resistant hash" from Setup). k_i' = k_i + Σ_j F_j(i).
7. **Unspecified values**: p (→ 2, implied by the mod-2 extractor), σ (→ 3.2), L (→ κ = 128 bits,
   "set the bit-length of x L = κ"; x = first L bits of SHA3-256(psw)), AES mode (→ AES-256-GCM),
   Dilithium level (→ Dilithium2/ML-DSA-44 with deterministic key_derive(seed = SHAKE256(K_u))),
   sid (server nonce), M (configurable).

---

## Part 3 — Implementation plan

### Packages
The user has installed the dependencies (numpy, cryptography, dilithium-py, ipykernel).
Check pyproject.toml / uv.lock before starting. Status: plan approved for storage only.
Do NOT start implementing until the group says so (this is a group project).

### `src/ris_sem_project/` layout
- `params.py` — `PARAM_I` (n=512, default), `PARAM_II` (n=595, run in Z_q[X]/(X^595+1), documented
  as not a power-of-two cyclotomic) presets + `setup(params, N, t, mu, rng) -> PublicParams`
  (samples a, a_0, a_1 uniformly; Setup, Sec. IV-A).
- `primitives/ring.py` — R_q arithmetic (add, negacyclic mul via FFT limbs, vectors 1×ℓ, (de)serialise).
- `primitives/sampling.py` — discrete Gaussian χ_σ, uniform R_q, Z_q.
- `primitives/gadget.py` — G, G^{-1} bit decomposition.
- `primitives/bp_prf.py` — a^F(x) and F_k(x) (Lemma 1).
- `primitives/extractor.py` — Ding signal S(·), extractor E(·,σ) (Def. 8).
- `primitives/secret_sharing.py` — Shamir over R_q (degree t−1), integer Lagrange coefficients at 0
  (+ check that a subset has integer λ_i), DKG Genshare/Genkey with χ_σ contributions (Def. 12).
- `primitives/toprf.py` — user blind / server eval / user combine (paper formula) + extract with
  register-time hint (Figs. 1–2, decisions 3–4).
- `primitives/hkdf.py`, `primitives/prf.py` — **lattice instantiation (user decision)**:
  PRF = BP PRF F_k(x) (Lemma 1, [80]), evaluated exactly (no noise → deterministic), p = 2.
  Keys: a {0,1}^{ℓn} bit string (K_u, dsk, PRK) packs into one R_q element (ℓ = 28 bits per
  coefficient, reduced mod q). Inputs: L-bit encodings (keyword/ρ/salt/counter → L bits).
  HKDF (Krawczyk): Extract PRK = F_{K_u}(salt); Expand dsk = F_PRK(enc(w, i)); output ℓn bits.
  AES-256 keys and the Dilithium seed are HKDF(K_u, "enc"/"sig") truncated to 256 bits.
  Each PRF call is a full L-step a_x evaluation, so HKDF/PRF/Retrieve will be slow-ish in Python
  (measure in notebook 05, don't guess).
- `primitives/signature.py` — Dilithium wrapper: gen_from_seed, sign, verify.
- `primitives/symmetric.py` — AES-256-GCM Enc/Dec.
- `primitives/linear_hash.py` — H for key-update commitments.
- `parties/` — existing abstract classes; extend `types.py` (`UserRecord.hint`, hint in
  `RegisterKeyMessage`/`TOPRFResponse`), then concrete `QPASEUser`, `QPASEServer` implementing the
  abstract methods; `Challenger`/adversaries later.
- `tests/` — stdlib `unittest` (no pytest install): ring mul vs naive, Shamir reconstruct, TOPRF
  determinism across runs, end-to-end register→login→outsource→retrieve, key update preserves K_u.

### Notebooks (`notebooks/`, import only from `src/`)
1. `01_preliminaries.ipynb` — ring, gadget, BP PRF, extractor, DKG.
2. `02_register_login.ipynb` — N servers, register, login (correct & wrong password, μ limit).
3. `03_outsource_retrieve.ipynb` — single + multi-keyword search.
4. `04_server_key_update.ipynb` — epoch update, users unaffected.
5. `05_costs.ipynb` — our own timings & message byte sizes per phase (README cites cells).

### Order of work
ring/sampling/gadget → BP PRF → extractor → secret sharing/DKG → TOPRF (test determinism) →
signature/symmetric/HKDF/PRF → concrete User/Server → key update → multi-keyword → notebooks → README.

## Verification
- `PYTHONPATH=src python3 -m unittest discover tests` (after packages installed via uv: `uv run python -m unittest discover tests`).
- TOPRF: same password → identical K_u over many logins and different t-subsets; wrong password → pk mismatch.
- End-to-end: register, login, outsource 3 docs under 2 keywords, retrieve returns exactly matching docs.
- Key update: after epoch change, login still yields same K_u and old data still retrievable.
- Run every notebook top-to-bottom; README numeric claims reference notebook + cell.
