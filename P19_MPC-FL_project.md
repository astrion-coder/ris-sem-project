# P19 — Multi-Party Computation based Federated Learning

**Paper:** R. Kanagavelu, Z. Li, J. Samsudin, Y. Yang, F. Yang, R. S. M. Goh, M. Cheah, P. Wiwatphonthana, K. Akkarajitsakul, S. Wang, "Two-Phase Multi-Party Computation Enabled Privacy-Preserving Federated Learning," *IEEE/ACM CCGRID 2020*, pp. 410–419. DOI 10.1109/CCGrid49817.2020.00-52

---

## 1. What the paper actually does

**Problem.** Peer-to-peer MPC model aggregation in federated learning requires every party to secret-share its model with every other party — O(n²) messages carrying *full model tensors*. This does not scale.

**Solution — two phases:**

- **Phase I — Committee election** (Algorithm 2). All *n* parties each generate a batch of *b* random votes, secret-share them, exchange shares, reconstruct the aggregate vote vector, and take the top-*m* voted parties as the aggregation committee.
  `Msg_Num = 2n² − 2n`, `Msg_Size = 2n²b − 2nb`
- **Phase II — Model aggregation** (Algorithm 3). Each party trains locally for *t* iterations, secret-shares its model into only *m* shares (one per committee member), uploads them; the committee members aggregate their shares, exchange among themselves, reconstruct the global model, and broadcast it.
  `Msg_Num = (nm + n + m − 1)e`, `Msg_Size = (nm + n + m − 1)e·s`

The key structural point: Phase I is O(n²) in *message count* but each message is tiny (*b* = 10 votes); Phase II is O(n) but each message is a full model of size *s*.

**Evaluation.**
- Use case: **induction-motor fault detection**, sensor data from Univ. of Tennessee (Hines' group), thermal-aging experiments, 121 time-domain features, 4 motors treated as 4 "companies", round-robin 3-train/1-test.
- Models: **SimpleNN** (121→2, size s = 242) and **ComplexNN** (one 60-neuron hidden layer, s = 7,380 — 30.5× larger).
- PyTorch 1.2.0, Python 3.7; Additive and Shamir secret sharing.
- Environments: Local-SingleServer (Xeon i7-7700, 32 GB), AWS-SameRegion (16 t3.medium in Singapore), AWS-CrossRegion (16 t3.medium across 8 regions).
- Committee **m = 3**, batch **b = 10**, local iterations **t = 3**, global epochs **e = 15**.

**Headline results:** at n = 128 on a single server, execution time reduced **25×** (peer-to-peer was 390.5 s). At n = 16, two-phase is **1.97×** faster same-region and **4.56×** faster cross-region. Federated accuracy ≈ centralised (SimpleNN balanced 0.935 federated vs 0.941 centralised; ComplexNN 0.945 vs 0.949), both above local-only. MPC overhead vs no-MPC: 2.03–2.12× for two-phase.

**Threat model, stated explicitly:** *"parties are honest-but-curious without collusion"*, and the committee assumption is *"no collusion among ≥3 participants."*

---

## 2. The concrete problems

### P1. The committee election is not secure against the adversary that matters

This is the central flaw. The paper's own text states the shared model *"could be reconstructed from the collusion among all selected committee members"* — so the committee is a **complete single point of privacy failure**, and its membership is chosen by an election protocol with no manipulation resistance.

Look at Algorithm 2: each party contributes *b* random numbers in [1, n], shares are summed, and the top-voted parties win. Nothing binds a party to its committed randomness. Concretely:
- **Last-revealer bias.** A party that reconstructs the aggregate before contributing (or that delays and adapts) can bias the outcome toward itself.
- **Self-voting.** Nothing prevents a party from voting for itself *b* times. With *b* = 10 and small *n*, a coalition of 3 colluding parties trivially wins all 3 committee seats — after which they can reconstruct every participant's model, and the privacy guarantee is **zero**.
- **No verifiable randomness.** No commitment phase, no VRF, no publicly verifiable beacon.

The probability that a coalition of *c* malicious parties captures all *m* seats is never analysed. It should have been the first analysis in the paper.

### P2. "Honest-but-curious without collusion" is contradicted by the design itself

The security of Phase II *depends entirely* on committee members not colluding — while the paper simultaneously assumes no collusion globally. This is circular: the assumption that makes the scheme secure is the assumption the scheme was supposed to remove the need for.

### P3. No defence against poisoning — MPC actively makes this worse

Secret-shared aggregation means **no one can inspect an individual update**. That is exactly the condition under which model poisoning and backdoor attacks thrive. A single malicious party can submit an arbitrarily scaled update; the committee sums shares blindly. The paper does no robustness analysis, and standard robust aggregators (Krum, trimmed mean, median) are **incompatible with plain additive/Shamir sharing** because they require comparing or ranking individual updates. This is a genuine open problem and an excellent project target.

### P4. Secure aggregation does not prevent inference from the *global* model

The paper's motivation cites attacks that extract data from shared models — but MPC only hides *individual* updates. Gradient-inversion, membership-inference, and property-inference attacks against the **aggregate** still work, especially with e = 15 epochs and n small. **No differential privacy anywhere**, and no measurement of what the global model leaks.

### P5. No dropout tolerance

Algorithms 2 and 3 assume every party responds. With additive sharing, **one missing share makes the sum unrecoverable**. Real FL over industrial IoT has constant churn. Bonawitz et al.'s secure aggregation (CCS'17) solved exactly this with a share-recovery mechanism; this paper has none, and never mentions the problem.

### P6. The evaluation is thin as machine learning

Four motors, 121 features, a **242-parameter** model, IID-ish partitioning by motor. "128 parties" on a single server means 128 *processes* splitting four datasets — that is a communication benchmark, not a federated-learning benchmark. Notably, the accuracy table shows federated *below* centralised for both models, with no statistical treatment.

### P7. Committee size *m* is never swept

m = 3 throughout, justified only by "usually acceptable." The paper never plots the **privacy/performance tradeoff in m** — the single most important design parameter, since m controls both collusion resistance and Phase II cost.

### P8. No non-IID evaluation

Every serious FL paper since McMahan et al. evaluates label-skewed and quantity-skewed partitions. Four motors round-robin is not a heterogeneity study.

---

## 3. Proposed contribution

**Recommended spine: _"Hardening two-phase MPC-FL: a manipulation-resistant committee election with an analysed collusion bound, MPC-compatible robust aggregation, and dropout tolerance — evaluated under non-IID data."_**

Every leg attacks a specific, named defect. This project is a good fit if you like distributed systems and applied crypto but do not want a full lattice-theory project.

### Improvement A — Faithful reimplementation with instrumentation *(foundation, ~2.5 weeks)*

1. Rebuild both phases with additive and Shamir sharing. Use **CrypTen** or **MP-SPDZ** rather than hand-rolled sharing (the paper's own related work cites CrypTen).
2. Verify the paper's message-count formulas empirically — instrument actual messages and bytes and check against `2n² − 2n` and `(nm + n + m − 1)e`.
3. Reproduce the scaling curves (n = 4…128) and the 25×/1.97×/4.56× speedups. Use Docker Compose with `tc netem` to emulate the cross-region latencies instead of paying for 16 EC2 instances across 8 regions.

### Improvement B — A committee election that resists manipulation *(the core contribution, ~3.5 weeks)*

**B1. Break the existing election.** Implement three concrete attacks against Algorithm 2 and measure the coalition's success probability vs coalition size *c* and vs *b*:
- self-voting (all *b* votes for self)
- last-revealer bias (withhold, observe partial aggregate, adapt)
- coordinated coalition voting (c parties concentrate votes on c targets)

Show empirically that a coalition of *c = m = 3* captures the committee with high probability. **That single plot justifies the whole project.**

**B2. Fix it.** Implement and compare three replacements:
- **Commit-and-reveal**: hash-commit votes, then reveal — kills last-revealer bias, but a non-revealing party can still abort. Handle with a timeout + share-recovery.
- **VRF-based sortition** (Algorand-style): each party computes `VRF_sk(seed, round)`, and those below a threshold join the committee. Self-selection is verifiable and unbiasable given an unpredictable seed. Ed25519-VRF (RFC 9381) is the practical choice.
- **Threshold-coin / publicly verifiable beacon**: derive the seed from a threshold BLS signature over the round number so no minority controls it.

**B3. Analyse it.** Derive the exact probability that a coalition of *c* out of *n* captures ≥ *k* of *m* seats under uniform sortition (hypergeometric), and plot **collusion-failure probability vs (c/n, m)**. This gives the paper's missing security parameter a number. Then choose *m* to hit a target failure probability — e.g. "for 20% adversarial parties, m = 3 fails with probability 0.008; m = 7 with a 3-of-7 reconstruction threshold fails with probability 5.8×10⁻⁴."

**B4. Use a threshold scheme properly.** Replace "all *m* committee members reconstruct" with **t-of-m Shamir**, so the committee tolerates *m − t* dropouts *and* requires *t* colluders (not 1) to breach. The paper uses Shamir but never exploits its threshold property — this is a clean, easily-defended improvement.

### Improvement C — Robust aggregation under secret sharing *(the hardest and most novel leg, ~3 weeks)*

The problem: Krum/median/trimmed-mean need to compare individual updates, but the whole point is that updates are hidden. Three tractable routes — implement at least one, ideally two, and compare:

1. **Norm-bounding via secure comparison.** Each party proves (or the committee verifies in MPC) that `‖Δw_i‖₂ ≤ B` and the update is clipped otherwise. Secure squared-norm computation is a dot product of shares — cheap. Clipping is the single most effective defence against scaling attacks and is genuinely MPC-friendly.
2. **Secure median / trimmed mean via MPC sorting.** Sorting *n* shared values requires a sorting network (Batcher's, O(n log²n) comparisons), each comparison being a secure protocol. Expensive but implementable in MP-SPDZ; measure the cost and report the crossover point where it becomes impractical.
3. **Committee-side pairwise-distance Krum in MPC.** Compute shared pairwise distances (dot products of shares), select the update with the smallest sum of *k* nearest distances. O(n²) secure dot products per round.

**Evaluate against real attacks:** sign-flipping, scaled-update (boosting), and a **semantic backdoor** (label a chosen fault pattern as "healthy"). Report main-task accuracy and backdoor accuracy vs number of malicious parties, for each defence. Report the MPC cost each defence adds.

### Improvement D — Dropout tolerance *(~1.5 weeks)*

Add a Bonawitz-style recovery: each party's share is itself *t*-of-*n* secret-shared among the others, so a dropout's contribution can be reconstructed by the survivors. Measure completion rate and round latency vs dropout rate (0–40%). Show the original protocol fails at any dropout rate above 0.

### Improvement E — Non-IID and differential privacy *(~2 weeks)*

1. Replace the 4-motor setup with a proper FL benchmark alongside it — **CIFAR-10 or FEMNIST** with Dirichlet(α) label skew, α ∈ {0.1, 0.5, 10} — while keeping the motor use case for continuity with the paper. Report accuracy vs α, and whether the two-phase committee changes convergence relative to peer-to-peer (it should not, but the paper never checks — the committee only aggregates, so *verify* that the aggregate is bit-identical to the peer-to-peer aggregate; this is a cheap and convincing correctness result).
2. Add **DP-SGD** noise (Opacus) on top of secure aggregation and plot the **(ε, accuracy)** curve. This closes P4: MPC hides individual updates, DP bounds what the *global* model leaks. Show the composition — the paper offers neither.

### Improvement F — Sweep committee size *(cheap, ~0.5 week)*

Plot the three-way tradeoff in *m*: communication cost (from the formula and measured), collusion-failure probability (from B3), and dropout tolerance (from D). Produce the design chart the paper should have shipped.

### Scope control

**A + B + D + F** is a tight, coherent project centred on the committee. Add **C** for real novelty (hardest), or **E** for ML breadth (easier). Don't do both C and E alone.

---

## 4. Rough timeline (14 weeks)

| Week | Work | Checkpoint artefact |
|---|---|---|
| 1 | Read the paper + Bonawitz et al. (CCS'17 secure aggregation) + Blanchard et al. (Krum) + Algorand sortition. Set up CrypTen / MP-SPDZ. | Reading notes; toolchain builds |
| 2 | Implement Phase I + Phase II with additive and Shamir sharing; verify correctness of the aggregate. | **Artefact A1:** working two-phase FL |
| 3 | Instrument messages/bytes; Docker + `netem` multi-region emulation; reproduce scaling curves to n = 128. | **Result R1:** reproduction of scaling claims |
| 4 | Implement the three election attacks; measure coalition capture probability vs (c, b, n). | **Result R2:** the election is manipulable |
| 5 | Implement commit-reveal and VRF sortition elections. | **Artefact A2:** hardened elections |
| 6 | Derive and validate the hypergeometric collusion bound; t-of-m threshold reconstruction. | **Result R3:** collusion-failure vs (c/n, m) |
| 7 | **Mid-semester review.** Consolidate R1–R3; write up the security analysis. | Mid-sem report + demo |
| 8 | Dropout tolerance: share-of-shares recovery. Completion rate vs dropout rate. | **Result R4** |
| 9 | Attack implementations: sign-flip, scaling, semantic backdoor on the motor + FEMNIST tasks. | **Result R5:** attack effectiveness baseline |
| 10 | Defence 1: secure norm-bounding/clipping in MPC. Measure cost and protection. | **Result R6a** |
| 11 | Defence 2: secure median or Krum via MPC. Measure the cost crossover. | **Result R6b** |
| 12 | Non-IID Dirichlet evaluation + DP-SGD (ε, accuracy) curve. | **Result R7** |
| 13 | Committee-size design chart; integration; write-up. | **Result R8** + draft report |
| 14 | Polish, reproducibility package, presentation. | Final deliverables |

Risk note: week 11 (secure median/Krum) is the most likely to overrun — MPC sorting is genuinely expensive. Keep norm-bounding (week 10) as the guaranteed defence and treat week 11 as conditional.

---

## 5. Expected deliverables

1. **`mpcfl-hardened/` repository**
   - `phases/` — Phase I and Phase II, additive and Shamir, t-of-m threshold
   - `election/` — original, commit-reveal, VRF sortition + attack implementations
   - `robust/` — MPC norm-bounding, secure median/Krum
   - `dropout/` — share-recovery protocol
   - `attacks/` — sign-flip, scaling, semantic backdoor
   - `deploy/` — Docker Compose + `netem` topologies emulating the paper's three environments
   - `eval/` — one command regenerates every figure
2. **Security analysis document** — a corrected threat model stating precisely what is protected against whom; the derivation of committee-capture probability; and an explicit statement of what MPC does *not* protect (global-model inference), with the DP composition that addresses it.
3. **Eight results:** R1 reproduction, R2 election manipulation, R3 collusion bound, R4 dropout tolerance, R5 attack baselines, R6a/b robust aggregation, R7 non-IID + DP tradeoff, R8 committee-size design chart.
4. **The design chart the paper omits** — committee size *m* against communication cost, collusion-failure probability, and dropout tolerance, with a recommended operating point for a stated adversarial fraction.
5. **Report (12–16 pages, IEEE format)** framed as: the two-phase idea is sound and the scalability claim holds, but the committee election makes the privacy guarantee vacuous under a realistic adversary — here is the fix, with numbers.
6. **Demo:** run 32 emulated parties across simulated regions; show a colluding coalition capturing the committee and reconstructing a victim's model under the original election, then failing under VRF sortition; then show a backdoor attack succeeding without norm-bounding and failing with it.

---

## 6. Tools, data, prerequisites

- **MPC:** CrypTen (PyTorch-native, easiest) or MP-SPDZ (more protocols, steeper curve). `tf-encrypted` is a third option.
- **FL:** Flower or a hand-rolled coordinator (the protocol is simple enough); PyTorch.
- **Crypto:** `python-ecdsa`/`libsodium` for Ed25519-VRF (RFC 9381); `py_ecc` or `blst` if you attempt threshold BLS.
- **DP:** Opacus.
- **Data:** the motor-fault use case is not public — substitute **CWRU Bearing Dataset** or **NASA C-MAPSS** (both public, same predictive-maintenance flavour), plus **FEMNIST** (LEAF) and **CIFAR-10** with Dirichlet partitioning for the FL benchmark.
- **Deployment:** Docker Compose + `tc netem`; optionally a handful of real cloud VMs for a validation point.
- **Background needed:** distributed systems + applied crypto. **No lattice theory.** Middle difficulty of the five — harder than P16, easier than P13/P14.

---

## 7. Risks

| Risk | Mitigation |
|---|---|
| MPC-based Krum/median too slow to evaluate at scale | Report the cost curve *as a result* ("secure Krum costs 340× a plain sum at n = 32") and rely on norm-bounding as the practical defence |
| Original motor dataset unavailable | Use CWRU/C-MAPSS from week 1; state the substitution explicitly in the report |
| CrypTen limitations on custom protocols | Fall back to MP-SPDZ for the comparison-heavy parts, keeping CrypTen for aggregation |
| 128-party experiments exceed the laptop | Run processes in Docker on a single machine as the paper did (it is the same setup), and validate at n ≤ 16 on real VMs |

---

## 8. Why this satisfies "must improve the work"

You show that the committee election — the mechanism the entire privacy guarantee rests on — can be captured by a small coalition, and you replace it with verifiable sortition plus a *t*-of-*m* threshold whose collusion-failure probability you derive and measure; you add robust aggregation that survives secret sharing, which the original explicitly cannot support; you add dropout tolerance without which the protocol fails on any real network; and you supply the non-IID, differential-privacy, and committee-size analyses the paper omits. The two-phase idea survives — you make it actually deployable, and you quantify each step.
