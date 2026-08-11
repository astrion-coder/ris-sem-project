# P14 — QPASE: Quantum-Resistant Password-Authenticated Searchable Encryption for Cloud Storage

**Paper:** J. Jiang and D. Wang, *IEEE Transactions on Information Forensics and Security*, vol. 19, pp. 4231–4246, 2024. DOI 10.1109/TIFS.2024.3372804

> Note: this is the strongest paper of the five — TIFS, a careful author (Ding Wang is a leading password-security researcher), formal proofs, and an unusually honest limitations discussion. That changes the shape of the project: you will not find a broken claim to knock down as in P12/P13. **The improvement here must come from what the paper explicitly leaves open, and it names those openings itself.**

---

## 1. What the paper actually does

**Goal.** Password-Authenticated Searchable Encryption (PASE): a user remembers only a password, and from it reconstructs a high-entropy key that encrypts and searches outsourced data — no key storage, no PKI. QPASE is the first PASE construction that is quantum-resistant.

**Core mechanism.** A **lattice-based threshold oblivious PRF (TOPRF)**, used to *re-randomize* the password into a user-specific key `K_u`. The user interacts with *t*-out-of-*n* servers; each server holds a share of the PRF key. Neither any single server nor a coalition below threshold learns the password, and the user learns nothing about the key shares. Authentication and key reconstruction happen **in the same flow**, which is where the computational saving over prior work comes from — the paper notes this "avoids the additional computational cost of commitments."

**Phases:** Setup, Registration, Login, Outsource, Retrieve, plus a **server key-update protocol**.

**Instantiations:** CRYSTALS-Dilithium for authentication/anti-tampering; HKDF + a PRF to derive the search key in `Outsource` and `Retrieve`.

**Security.** Formal proofs of *authentication security* and *IND-CKA* under quantum adversaries. Notably, the analysis uses the **Zipf law for password distributions** (Wang et al.) rather than the conventional uniform-guessing assumption, giving a tighter and more realistic bound on online-guessing advantage.

**Parameters.** Selected with the `lwe-estimator` under the core-SVP quantum cost model (classical 2^{0.292β}, quantum 2^{0.268β}):
- `q = 2^28 − 57, n = 512, β = 342` → **100-bit classical / 92-bit quantum**
- `q = 2^28 − 57, n = 595, β = 478` → **128-bit quantum**

**Extensions given:** multi-keyword search; server-side key update transparent to users.

**The paper's own stated limitation (verbatim in the text):** *"our QPASE has more communication costs than PASE [14], and this is a limitation of our scheme. Therefore, it may be not suitable for scenarios with low network bandwidth."* Concretely: the TOPRF LWE instance is **~0.5 MB**, communication **grows linearly in the number of servers**, and the registration-phase public key alone is **≥ 2.2 MB** (Dilithium).

---

## 2. The concrete gaps — the honest list

### G1. Communication cost is the acknowledged weak point, and nobody has attacked it

~0.5 MB per TOPRF instance, linear in *n* servers, plus ≥2.2 MB registration. For a mobile client on a metered or lossy link, this is the difference between usable and unusable. The paper argues the gap shrinks as outsourced file size grows — true, but it does not help the *login* path, which is fixed cost and happens every session. **This is the single most promising improvement target, and the authors hand it to you.**

### G2. No implementation on constrained hardware, and no network-condition evaluation

Benchmarks are computational cost comparisons. There is no measurement over a real network — no RTT sensitivity, no packet loss, no measurement on a phone or an IoT-class device. For a scheme whose stated weakness is *communication*, evaluating only computation leaves the actual limitation unmeasured.

### G3. Threshold structure is proved but not stress-tested

The TOPRF is *t*-out-of-*n*. What happens as *t* and *n* vary? What is the latency when the slowest server is cross-region? What is the failure behaviour when *n − t + 1* servers are down? None of this is measured — and it directly governs deployability.

### G4. No forward/backward privacy for dynamic data

QPASE handles Outsource and Retrieve. It does not support **update or deletion** of outsourced documents with the standard dynamic-SSE guarantees. The paper's own related-work section discusses forward security (updates don't leak against past queries) and backward security (deleted data can't be found by later queries) for DSSE — then does not provide them. In any real cloud storage product, files change.

### G5. Leakage from search patterns is unquantified — no leakage-abuse evaluation

IND-CKA is proved, but IND-CKA permits **access-pattern and search-pattern leakage**. The entire leakage-abuse attack literature (Islam–Kuo–Kantarcioglu; Cash et al.; Blackstone et al.; Oya–Kerschbaum's IHOP) shows that with modest auxiliary knowledge an adversary recovers a large fraction of queried keywords from access patterns alone. **QPASE is not evaluated against any of these.** A proof of IND-CKA is not a defence against IKK/count/IHOP attacks, and this gap exists in essentially every SE paper — including this one.

### G6. Online-guessing rate limiting is assumed, not engineered

Zipf-based analysis bounds an online adversary's success given `q_s` guesses. But nothing in the protocol *enforces* a limit on `q_s` — that is delegated to unspecified server-side policy. With *n* servers, a distributed attacker can spread guesses across servers to evade per-server rate limits. The paper does not analyse distributed guessing.

### G7. Password-change and account-recovery are absent

Users forget and change passwords. QPASE has a *server*-key-update protocol but no *user*-password-change protocol. Naively re-running registration invalidates every previously derived search key and requires re-encrypting the entire corpus.

---

## 3. Proposed contribution

**Recommended spine: _"Making QPASE deployable: cutting the login-path communication cost, measuring it on real networks and real devices, and closing the dynamic-update and password-change gaps."_**

This is the honest framing for a strong paper — you extend rather than refute, and every item traces to a gap the authors either state or leave visibly open.

### Improvement A — Faithful implementation + the missing communication measurement *(foundation, ~4 weeks)*

1. Implement QPASE at **both** published parameter sets (n = 512 / β = 342, and n = 595 / β = 478). Use `liboqs` or the reference Dilithium implementation for signatures; build the TOPRF over a lattice library (OpenFHE, `lattigo`, or NTL).
2. Instrument **every message**: exact byte counts per phase (Registration, Login, Outsource, Retrieve, Key-Update) and per server. Verify or refute the paper's stated ~0.5 MB and ≥2.2 MB figures. Publish a **wire-format byte budget table** — the paper has no such table.
3. Deploy across **real network conditions** using `tc netem`: RTT ∈ {5, 50, 150, 300} ms, loss ∈ {0, 0.5, 2}%, bandwidth ∈ {1, 10, 100} Mbps. Measure end-to-end login latency, not just CPU time.
4. Run the client on a constrained device — Raspberry Pi 4 or an Android phone via JNI — and report login latency and peak memory.

**Expected finding:** login latency dominated by transfer, not compute, on anything below ~50 Mbps; the paper's computational advantage over PASE becomes irrelevant at typical mobile RTT. That inversion is a publishable result on its own.

### Improvement B — Reduce the communication cost *(the core contribution, ~4 weeks)*

Three attacks on the byte count, in increasing ambition. Do at least two.

**B1. Seed-expansion and compression of the LWE instance.** The 0.5 MB TOPRF instance is dominated by uniformly random matrix material. Standard NIST-PQC practice: transmit a **32-byte seed** and expand it with SHAKE-128 at both ends. Combined with **modulus/coefficient compression** (dropping low-order bits of the LWE samples, as Kyber does, at a controlled noise cost), the instance should shrink by a large factor. You must re-run the **`lattice-estimator`** to confirm the compressed parameters still hit 128-bit quantum security — this is the part that makes it a research contribution rather than an engineering trick.

**B2. Ring/module-LWE instantiation of the TOPRF.** The construction uses plain LWE with an `n × m` matrix. Moving to **Module-LWE** (as ML-KEM/ML-DSA do) replaces matrix material with polynomial rings, typically shrinking transcripts by an order of magnitude at the same security level. This is a real design change with real risk — the oblivious/threshold structure must be re-derived over rings — so scope it carefully and state clearly which security arguments carry over and which need re-proof.

**B3. Amortise the registration public key.** The ≥2.2 MB Dilithium public key need not be re-sent per session. Cache with a short **key-commitment** (hash) and transmit the full key only on first contact or rotation. Trivial engineering, meaningful saving; measure it.

**Deliverable for B:** a communication-vs-security frontier plot — bytes on the login path against quantum security level, for original QPASE, each of your variants, and PASE (the non-quantum baseline). This directly answers the limitation the authors flagged.

### Improvement C — Threshold and failure behaviour under geo-distribution *(~2 weeks)*

Deploy *n* servers across cloud regions. Sweep (t, n) ∈ {(2,3), (3,5), (5,9)}. Measure:
- login latency vs *t* (you wait for the *t*-th slowest server — a tail-latency problem)
- availability under *k* server failures
- **hedged requests** (contact *t + δ* servers, use the first *t* responses) as a tail-latency mitigation; report the bandwidth/latency tradeoff

Also implement and measure the paper's **server key-update protocol**: how long does rotating all *n* shares take, and is it genuinely invisible to a user mid-session?

### Improvement D — Distributed online-guessing defence *(sharp, ~2 weeks)*

Show the gap in G6 concretely: an attacker splitting guesses across *n* servers gets *n* × the per-server allowance. Then fix it:
- **Threshold-side counting:** servers hold shares of a per-account guess counter and refuse participation once the reconstructed count exceeds a threshold — requires a small MPC or a share-of-counter protocol.
- Re-derive the Zipf-based security bound with the *aggregate* `q_s` and show the improvement.

Evaluate against real password distributions — **RockYou** (32M) and the leaked-password frequency lists Wang et al. use — to instantiate the Zipf parameters empirically rather than assuming them.

### Improvement E — Dynamic updates with forward/backward privacy *(~2.5 weeks)*

Add `Update(add/del)` to QPASE with an explicit leakage function, targeting **forward privacy** and **Type-II backward privacy**. The standard technique (Bost's Σοφος-style trapdoor permutation chain) needs a post-quantum replacement — use a hash-chain/puncturable-PRF construction instead, and state the leakage profile formally. Measure update throughput and index-size growth.

### Improvement F — Password change without re-encryption *(~1.5 weeks)*

Design a `PwdChange` protocol: because `K_u` is derived through the TOPRF, a password change should be implementable as a **re-randomisation of the TOPRF key shares** plus a key-wrapping layer — the data-encryption key stays fixed, only the wrapping changes. Measure the cost and prove it doesn't weaken the offline-guessing resistance. This closes an obvious deployment gap in one clean step.

### Improvement G — Leakage-abuse evaluation *(optional but high-impact, ~2 weeks)*

Implement **IKK** and **IHOP** (Oya–Kerschbaum, USENIX Sec'22) against QPASE's access/search patterns using an auxiliary keyword distribution from a public corpus (Enron email is the standard benchmark). Report query-recovery rate vs auxiliary-knowledge quality. Then evaluate a padding/volume-hiding countermeasure and its bandwidth cost — noting that QPASE already has a bandwidth problem, so the interaction is interesting.

### Scope control

**A + B + C** is a strong, coherent project squarely aimed at the authors' stated limitation. Add **D** or **F** if time allows (both are self-contained). **E** and **G** are each large enough to be a project on their own — take one, not both.

---

## 4. Rough timeline (14 weeks)

| Week | Work | Checkpoint artefact |
|---|---|---|
| 1 | Read QPASE + Jarecki–Krawczyk–Xu (TOPRF/OPAQUE), Chen et al.'s PASE [14], Albrecht et al. parameter methodology. Toolchain: `liboqs`, `lattigo`/OpenFHE, `lattice-estimator`. | Reading notes; builds working |
| 2 | Implement the lattice TOPRF; unit tests for obliviousness and threshold reconstruction. | `toprf` module passing tests |
| 3 | Full QPASE: Setup/Registration/Login/Outsource/Retrieve + Dilithium + HKDF. Correctness across both parameter sets. | **Artefact A1:** working QPASE |
| 4 | Byte-level instrumentation; wire-format budget table. Verify the 0.5 MB / 2.2 MB claims. | **Result R1:** communication budget |
| 5 | Network-emulation harness (`tc netem`) + Raspberry Pi / Android client. Latency vs RTT/loss/bandwidth. | **Result R2:** deployability measurement |
| 6 | B1: seed expansion + coefficient compression. Re-run `lattice-estimator` to confirm security. | **Result R3:** compressed variant |
| 7 | **Mid-semester review.** B3: public-key caching. Consolidate R1–R3. | Mid-sem report + demo |
| 8–9 | B2: Module-LWE TOPRF variant. Document which security arguments transfer. | **Artefact A2:** MLWE-QPASE |
| 10 | Communication-vs-security frontier plot across all variants + PASE baseline. | **Result R4:** the headline figure |
| 11 | Geo-distributed (t, n) sweep; hedged requests; server key-update timing; failure behaviour. | **Result R5** |
| 12 | Chosen extra: D (distributed guessing defence) **or** F (password change). Implement + measure. | **Result R6** |
| 13 | Full write-up; security discussion for all modified components. | Draft report |
| 14 | Polish, reproducibility package, presentation. | Final deliverables |

Risk note: weeks 8–9 (Module-LWE) are the most likely to overrun. Go/no-go at end of week 7 — if B1 already delivers a large enough saving, drop B2 and expand C and D instead.

---

## 5. Expected deliverables

1. **`qpase-plus/` repository**
   - `toprf/` — lattice TOPRF, plain-LWE and Module-LWE variants
   - `qpase/` — full protocol, both parameter sets
   - `params/` — `lattice-estimator` scripts + security tables for original *and* compressed parameters
   - `net/` — network-emulation harness, mobile/Pi client
   - `eval/` — one command regenerating every figure
2. **The communication budget table the paper omits** — exact bytes per message, per phase, per server, for QPASE and every variant.
3. **Six results:** R1 byte budget, R2 latency vs network conditions & device class, R3 compressed-parameter security + size, R4 communication-vs-security frontier, R5 threshold/geo-distribution behaviour, R6 the chosen extra.
4. **Security analysis document** — for every modification (compression, MLWE, caching, and whichever of D/E/F you pick): what changes in the security argument, what carries over, what would need re-proof. Be explicit about proof gaps; a semester project is allowed to leave a full proof as future work, but not to pretend there is none needed.
5. **Report (12–16 pages, IEEE format)**, framed as an extension: "QPASE identifies communication cost as its limitation; we quantify it, reduce it by X×, and measure the result under real network conditions."
6. **Demo:** login + keyword search from a phone over an emulated 3G link, side by side, original vs optimised QPASE — the latency difference should be visible to the eye.

---

## 6. Tools, data, prerequisites

- **PQ crypto:** `liboqs` (Dilithium/ML-DSA, Kyber/ML-KEM), OpenFHE or `lattigo`, `lattice-estimator` (Sage).
- **Networking:** Linux `tc netem`, Docker Compose or multi-region cloud VMs.
- **Devices:** Raspberry Pi 4 (or Android via NDK) for the constrained client.
- **Password data:** RockYou frequency list and other public leaked-password frequency corpora, for Zipf parameter fitting.
- **Corpus for leakage attacks (if doing G):** Enron email dataset.
- **Background needed:** lattice crypto, threshold protocols, and enough systems skill to do network measurement properly. This is the most technically demanding of the five papers — but also the most likely to produce something genuinely publishable.

---

## 7. Risks

| Risk | Mitigation |
|---|---|
| Faithful TOPRF implementation is hard and the paper omits some engineering detail | Contact the authors early (Ding Wang's group is responsive); fall back to a simplified but *documented* instantiation and state the deviation |
| Module-LWE variant breaks the obliviousness argument | Treat as an explicitly exploratory branch; report negative results honestly — "MLWE reduces bytes by X but the threshold reconstruction requires Y, which we could not prove secure" is a legitimate finding |
| Nothing to "fix" since the paper is solid | This is the point of the framing — the contribution is *deployability*, and the authors named the target themselves. Lead with that in the report's motivation |
| Scope too large | Freeze at end of week 7: A + B1 + B3 + C guaranteed; B2 and one of D/E/F/G conditional |

---

## 8. Why this satisfies "must improve the work"

You take the limitation the authors explicitly state — communication cost, "may be not suitable for scenarios with low network bandwidth" — and you (i) measure it properly for the first time, including on real networks and constrained devices, (ii) reduce it by concrete cryptographic means with parameters re-validated at the same quantum security level, (iii) characterise threshold/geo-distribution behaviour that governs deployability, and (iv) close a named functional gap (dynamic updates, distributed guessing, or password change). None of this is reimplementation, and all of it is measurable against the published scheme.
