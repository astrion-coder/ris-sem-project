# P13 — PPSEB: A Postquantum Public-Key Searchable Encryption Scheme on Blockchain for E-Healthcare

**Paper:** G. Xu, S. Xu, Y. Cao, F. Yun, Y. Cui, Y. Yu, K. Xiao, *Security and Communication Networks*, 2022, Article 3368819, 13 pages. DOI 10.1155/2022/3368819

---

## 1. What the paper actually does

**Construction.** A lattice-based Public-key Encryption with Keyword Search (PEKS) scheme with *forward security*, built from the Agrawal–Boneh–Boyen lattice toolkit:

- Six algorithms: `Initialization`, `KeyExt`, `PPSEB.PEKS`, `PPSEB.Trapdoor`, `PPSEB.Verification`, `PPSEB.Decrypt`
- Lattice primitives used: `TrapGen`, `SamplePre`, `SampleLeft`, `SampleRight`, `NewBasisDel`, `SampleRwithBasis`
- **Forward security** via time-period key evolution: the receiver public key at period *j* is `pk_r‖j = pk_r‖j−1 · R_j^{-1}` where `R_j = H1(pk_r‖j)`, and the secret basis is re-derived with `NewBasisDel`. Compromise at period *j* does not expose ciphertexts from periods < *j*.
- Ciphertext (Algorithm 3): `CT_j1 = μᵀB_j + noi_j + y_j⌊q/2⌉`, `CT_j2 = (pk_r‖j β_j^{-1})ᵀ B_j + noiv_j`, with `β_j = H2(w‖j)`
- Trapdoor (Algorithm 4): `NewBasisDel(pk_r‖j, β_j, sk_r‖j, δ_j)` → `sk_w‖j`, then `SamplePre(pk_r‖j β_j^{-1}, sk_w‖j, μ, σ_j)` → `Trap_w‖j`
- Test (Algorithm 5): compute `y_j = CT_j1 − Trapᵀ CT_j2`, accept iff every coordinate is within `q/4` of `q/2`

**Blockchain role.** A five-layer architecture with an added data layer; the *smart contract* performs the keyword search (`Test`), replacing the untrusted third-party server. Master node validates, all nodes run consensus, affiliate nodes verify the transaction slip.

**Security.** IND-CKA reduced to LWE in the random oracle model. Reduction loss: adversary advantage *p* ⇒ LWE solved with probability *p/2m* (the challenger must guess the break period *j\**, hence the 1/m).

**Evaluation.** C++, macOS, Intel Core i7, 16 GB RAM, 200-trial averages. Compared against [3], [5], [28], [29]. Headline: at 180 retrieved keywords, scheme [5] takes 7.2 s and PPSEB takes 0.477 s (15.09×). Trapdoor size claimed 1/4 of [29].

---

## 2. The concrete problems

### P1. The blockchain is never implemented — and if it were, `Test` would not fit on-chain

The paper describes a five-layer blockchain architecture, chaincode retrieval, master/affiliate node validation, and consensus. **None of it appears in Section 6.** The evaluation measures only C++ crypto microbenchmarks (trapdoor size, PEKS size, testing time). There is no chain, no smart contract, no consensus latency, no storage cost, no gas.

This matters more than a missing experiment, because the on-chain `Test` is almost certainly infeasible. `Test` requires computing `CT_j1 − Trap_w‖jᵀ · CT_j2` over `Z_q^{m×l}` with the constraint `m > 2n log q`. For a plausible parameter set (n = 256, q ≈ 2^24, so m > 12288), a single `Test` is a matrix–vector product with ~10⁴–10⁵ modular multiplications — per document, per query, executed redundantly by **every validating node**. Nothing in the paper acknowledges this.

### P2. The "postquantum ⇒ KGA-resistant" claim is a category error

The paper repeatedly claims PPSEB resists **keyword guessing attacks** because it is built on LWE (Contribution 1: *"Postquantum KGA: PPSEB can resist KGA attacks"*).

But KGA in public-key searchable encryption has nothing to do with the hardness of the underlying problem. In any PEKS scheme, **the encryption key is public**. An adversary who observes a trapdoor `Trap_w‖j` can:
1. enumerate candidate keywords `w'` from a dictionary,
2. run `PPSEB.PEKS(pk, w')` himself — he needs only the public key,
3. run `Test(Trap_w‖j, CT')` and check for a match.

Medical keyword spaces are tiny and highly structured — ICD-10 has ~70,000 codes, and real clinical note vocabularies are Zipfian with a few thousand high-frequency terms. Offline KGA over that space is trivially feasible **regardless of whether the hard problem is LWE or discrete log**. Lattices buy you resistance to Shor, not resistance to dictionary enumeration. The paper's Section 5 proves IND-CKA (ciphertext indistinguishability) and simply does not model the KGA adversary.

**This is the most attackable claim in the paper and the best foundation for the project.**

### P3. Search is linear in the corpus, on-chain

`Test` must be run against every stored ciphertext to find matches. There is no index. For a hospital with 10⁶ documents, one query = 10⁶ lattice `Test` operations. The paper's timing curve goes up to 180 keywords and stops.

### P4. Concrete parameters are never given

The paper says only `m > 2n log q, q ≥ 3` — a definitional constraint, not a parameter set. **No values of n, q, m, σ appear anywhere.** Therefore:
- the claimed security level is unknown (is this 80-bit? 128-bit? classical or quantum?),
- the 15× speedup over [5] is uninterpretable, because [5] is a *pairing-based* scheme whose parameters *are* pinned down by its curve choice,
- the trapdoor-size comparison ("a quarter of [29]") cannot be checked.

Comparing a lattice scheme at unknown parameters against pairing schemes at known parameters is not a fair benchmark.

### P5. No dynamic operations, no backward security

Forward security (past ciphertexts safe after key compromise) is proved. But there is no **document deletion**, no **backward privacy** (deleted documents must not be matched by later trapdoors), and no revocation. In an EHR setting, deletion is a legal requirement (GDPR Art. 17 / DPDP Act erasure).

### P6. Single keyword only

No conjunctive, disjunctive, or range queries. Real clinical queries are conjunctive ("diabetes AND metformin AND 2023").

### P7. "Medical data extremely close to actual applications" is unverifiable

No dataset is named, no corpus size, no keyword distribution. Reproducibility is zero.

---

## 3. Proposed contribution

**Recommended spine: _"PPSEB is not KGA-resistant: a working attack, a lattice-based PAEKS repair, and a verifiable off-chain search architecture that makes the blockchain claim real."_**

This gives you (a) a demonstrated attack, (b) a principled fix with a proof sketch, (c) an engineering contribution that fixes the unimplemented half of the paper. Three legs, all concrete.

### Improvement A — Implement PPSEB properly with pinned parameters *(foundation, ~3 weeks)*

You cannot critique what you have not built.

1. Implement all six algorithms over **NTL** or **OpenFHE**/**PALISADE** (or `lattigo` if you prefer Go). `TrapGen`, `SamplePre` (Gentry–Peikert–Vaikuntanathan / Micciancio–Peikert), `NewBasisDel` are the hard parts — GPV sampling is the classic implementation pitfall, budget time for it.
2. **Pin parameters at a stated security level.** Use the [lattice-estimator](https://github.com/malb/lattice-estimator) (successor to `lwe-estimator`) to select `(n, q, σ, m)` giving **128-bit classical / ~110-bit quantum** under the core-SVP model with cost exponents 0.292β (classical) / 0.265β (quantum). Publish the estimator script. This single artefact is more useful than the paper's entire Section 6.
3. Re-benchmark against the baselines **at matched security level** — pairing schemes on BLS12-381 (~128-bit) via `RELIC` or `mcl`, not at whatever level [5] happened to use.

**Expected finding:** the 15× advantage shrinks substantially or reverses once parameters are matched, and trapdoor/ciphertext sizes are far worse than the paper's normalised plots suggest. Report honestly with byte counts, not unlabelled bar charts.

### Improvement B — Demonstrate the KGA, then fix it with lattice-based PAEKS *(the core, ~4 weeks)*

**B1. The attack.** Build a keyword dictionary from a real medical vocabulary — ICD-10-CM codes (~70k), or extract the keyword distribution from **MIMIC-IV-Note** (requires PhysioNet credentialing; **Synthea**-generated synthetic EHR is the zero-friction fallback). Then:
- Adversary = the blockchain itself (any validating node) or a network observer holding `pk` and one trapdoor.
- Enumerate the dictionary, generate `PPSEB.PEKS(pk, w')`, run `Test`.
- Report **keyword recovery rate vs dictionary size and vs adversary compute budget**, plus wall-clock time to recover one keyword.

Prediction: recovery of a top-1000-frequency keyword in well under a second per trapdoor. That is your headline result.

**B2. The fix — lattice PAEKS.** Move from PEKS to **Public-key Authenticated Encryption with Keyword Search**: the *sender* (data owner) signs/authenticates the searchable ciphertext with **its own secret key**, so ciphertexts become unforgeable. An adversary holding only `pk_receiver` can no longer generate valid searchable ciphertexts for candidate keywords, killing the offline enumeration.

Concretely, augment `PPSEB.PEKS` to bind the ciphertext to a sender–receiver shared value: derive `β_j = H2(w ‖ j ‖ DH-analogue(sk_sender, pk_receiver))` where the "DH-analogue" is a lattice key-encapsulation (Kyber/ML-KEM) or a lattice-based non-interactive shared secret. Then:
- **Ciphertext indistinguishability against KGA (CI-KGA)** and **trapdoor privacy (TP-KGA)** become the target security notions — state them as games, mirroring Huang–Li's PAEKS definitions, and give the reduction to DLWE.
- Preserve the forward-security key-evolution structure from the original (`NewBasisDel` chain) — showing that PAEKS and forward security *compose* is itself a contribution.

**B3. Re-run the attack** against your PAEKS variant and show recovery rate drops to the trivial baseline. Report the cost: extra ciphertext bytes, extra ms per `PEKS` call.

### Improvement C — Make the blockchain claim real: verifiable off-chain search *(~3 weeks)*

Show why on-chain `Test` fails, then fix the architecture:

1. **Measure the infeasibility.** Implement `Test` as Hyperledger Fabric chaincode (Go). Measure per-`Test` latency, and extrapolate: at N documents and V validating nodes, total network work = N × V lattice tests per query. Produce the graph that the paper should have had.
2. **Redesign:** keep an **encrypted keyword index off-chain** (bucketed by `H(β_j)` so `Test` runs only against candidate buckets — reducing search from O(N) to O(N/B + matches)); put on-chain only:
   - a Merkle root of the index at each time period *j*,
   - the query/response audit record.
3. **Add verifiability** so the untrusted searcher cannot cheat — the paper's entire motivation for using a blockchain. Two options, pick one:
   - **Merkle-proof approach (recommended, tractable):** the searcher returns matched document IDs plus a Merkle inclusion proof, *and* for soundness on non-matches, a sorted-index non-membership proof. Client verification is O(log N) hashes.
   - **Sampling audit approach (cheaper):** client re-runs `Test` on a random ε-fraction of the index and detects a cheating server that suppresses a fraction *f* of results with probability 1−(1−ε)^{fN}.
4. **Measure the win:** on-chain bytes/query and validator CPU/query, before vs after. Expect 3–5 orders of magnitude.

### Improvement D — Dynamic updates with backward privacy *(optional, ~2 weeks)*

Add `Add`/`Delete` over the keyword index with an explicit leakage function, targeting **Type-II backward privacy** (Bost–Minaud–Ohrimenko taxonomy). Measure update cost and state the leakage profile formally — the original paper states no leakage function at all.

### Improvement E — Conjunctive queries *(optional, ~1.5 weeks)*

Extend to conjunctive search. The cheap route: intersect single-keyword result sets client-side (leaks per-term result sets). The better route: an OXT/BXT-style approach adapted to the lattice setting. Report the leakage difference.

### Scope control

**A + B + C** is the project. D and E are stretch goals. B alone (attack + PAEKS fix + proof) would be a good project if the implementation in A proves harder than expected — GPV sampling can eat weeks.

---

## 4. Rough timeline (14 weeks)

| Week | Work | Checkpoint artefact |
|---|---|---|
| 1 | Read PPSEB + Agrawal–Boneh–Boyen (EUROCRYPT'10) + Huang–Li PAEKS (Inf. Sci. 2017). Set up NTL/OpenFHE. | Reading notes; toolchain builds |
| 2 | Implement `TrapGen`, `SamplePre`, `SampleLeft/Right`. Unit-test correctness (short basis norms, sample distributions). | `lattice_core` passing tests |
| 3 | Implement `NewBasisDel` + the full six-algorithm PPSEB. Verify correctness: `Test` accepts matching keywords, rejects non-matching, across 200 trials. | **Artefact A1:** working PPSEB |
| 4 | Parameter selection with `lattice-estimator` at 128-bit classical. Matched-security benchmarking vs pairing baselines (RELIC/BLS12-381). | **Result R1:** honest size/time table |
| 5 | Build the medical keyword corpus (ICD-10 / Synthea). Implement the KGA. | Dictionary + attack harness |
| 6 | Run KGA: recovery rate vs dictionary size, vs budget, vs keyword frequency rank. | **Result R2:** the attack |
| 7 | **Mid-semester review.** Design the lattice-PAEKS variant; write the CI-KGA/TP-KGA game definitions. | Mid-sem report + security definitions |
| 8 | Implement PAEKS variant preserving forward security. | **Artefact A2:** PPSEB-PAEKS |
| 9 | Re-run KGA against PAEKS; measure overhead (bytes, ms). Write the reduction to DLWE. | **Result R3:** the fix + proof sketch |
| 10 | Fabric chaincode implementing on-chain `Test`; measure per-`Test` cost, extrapolate to N×V. | **Result R4:** infeasibility measurement |
| 11 | Off-chain bucketed index + on-chain Merkle commitment; implement verification. | **Artefact A3:** verifiable search |
| 12 | End-to-end evaluation: query latency vs corpus size (10³ → 10⁶ docs), on-chain bytes/query, verification cost. | **Result R5** |
| 13 | Write-up: full report, security definitions, proofs, all figures. | Draft report |
| 14 | Polish, reproducibility package, presentation. | Final deliverables |

Highest-risk weeks: 2–3 (GPV/`SamplePre` implementation). If it slips past week 4, drop Improvement C's chaincode work and keep the analytical infeasibility argument instead.

---

## 5. Expected deliverables

1. **`ppseb-plus/` repository**
   - `crypto/` — full PPSEB implementation (C++/NTL or OpenFHE) with correctness tests
   - `params/` — `lattice-estimator` script producing the chosen parameter set with security estimates
   - `attack/` — KGA harness + medical keyword dictionary builder
   - `paeks/` — the authenticated variant
   - `chain/` — Fabric chaincode + off-chain index + Merkle verification
   - `bench/` — one command regenerating every figure
2. **The parameter table the paper omits** — `(n, q, m, σ)` with classical and quantum security estimates, ciphertext/trapdoor/public-key sizes in **bytes**, and per-operation timings.
3. **Five results:** R1 matched-security benchmark, R2 KGA recovery rates, R3 PAEKS mitigation + overhead, R4 on-chain `Test` infeasibility, R5 verifiable off-chain search cost.
4. **Security-definitions document** — IND-CKA (as in the paper), plus CI-KGA and TP-KGA for your variant, with the DLWE reduction written out and the reduction loss stated explicitly (the original's 1/m period-guessing loss should be discussed too).
5. **Report (12–16 pages, IEEE/LNCS format)** with a "claims audit" table: each PPSEB claim → *holds / holds with caveats / does not hold*, and evidence.
6. **Demo:** query a 10⁶-document encrypted index, verify the result against the on-chain Merkle root, and show a live KGA succeeding against PPSEB and failing against your PAEKS variant.

---

## 6. Tools, data, prerequisites

- **Lattice crypto:** NTL 11.5+, or OpenFHE / PALISADE, or `lattigo` (Go). `lattice-estimator` (Python/Sage) for parameter selection.
- **Pairing baselines:** RELIC or `mcl` on BLS12-381.
- **Blockchain:** Hyperledger Fabric 2.5, Go chaincode.
- **Medical corpora:** ICD-10-CM code list (free, CDC/CMS); **Synthea** synthetic EHR generator (no credentialing needed); MIMIC-IV-Note only if you already hold PhysioNet credentials — don't let this block you.
- **Background needed:** comfort with lattices (SIS/LWE, Gaussian sampling, trapdoors). If your background is systems rather than crypto theory, this project is the hardest of the five — consider P16 or P19 instead.

---

## 7. Risks

| Risk | Mitigation |
|---|---|
| GPV `SamplePre` / `NewBasisDel` implementation is genuinely hard | Use OpenFHE's trapdoor sampling primitives rather than writing from scratch; budget weeks 2–3 and have a go/no-go at week 4 |
| Security proof for PAEKS variant is beyond scope | Deliver formal *game definitions* + a reduction *sketch* with the key hybrid steps, and be explicit that full proof is future work. This is acceptable for a semester project if the attack and implementation are solid |
| MIMIC access delays | Use Synthea + ICD-10 from day one |
| Fabric integration slips | Fall back to a measured single-node `Test` cost × analytical N×V extrapolation |

---

## 8. Why this satisfies "must improve the work"

You demonstrate that the paper's flagship security claim (KGA resistance) does not hold, with a working attack on your own faithful implementation; you repair it with a lattice-based authenticated construction that preserves the original's forward security; you supply the concrete parameter set and matched-security benchmark the paper never gives; and you replace an unimplemented, infeasible on-chain search with a verifiable off-chain design whose cost you measure. Each item is a measurable delta against the published scheme.
