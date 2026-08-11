# P12 — BSFR-SH: Blockchain-Enabled Security Framework Against Ransomware Attacks for Smart Healthcare

**Paper:** M. Wazid, A. K. Das, S. Shetty, *IEEE Transactions on Consumer Electronics*, 69(1):18–28, Feb 2023. DOI 10.1109/TCE.2022.3208795

---

## 1. What the paper actually does

**Architecture — five phases**, each backed by one of two private blockchains:

1. Backup of healthcare data as encrypted transactions on blockchain `BC_DTBU`
2. Ransomware data collection + signature/feature building on blockchain `BC_SigRW` (honeypots named as the source)
3. Ransomware detection & analysis — an ML classifier over the collected features
4. Mitigation (isolate/kill the infected node, triggered by an authorised cloud server `CS_l`)
5. Data recovery from `BC_DTBU`

**Implementation as reported (Section VII):** Java + Eclipse IDE 2019-12, Windows 11, i5 9th-gen, 8 GB RAM. Four miner nodes. PBFT with voting-based mining. Three cases: 5, 10, 15 blocks × 100 transactions each. Computation time 3.10 / 4.17 / 5.71 s (backup chain) and 4.36 / 5.54 / 6.76 s (ransomware chain); TPS 161/240/263 and 115/181/222.

**ML side:** Random Forest, Logistic Regression, Decision Tree, KNN on the **BitcoinHeist Ransomware Address Dataset** (UCI). Best result 98.98% accuracy and F1 = 0.990, from the **decision tree**. Compared against Almashhadani [11], Hwang [12], Sharmeen [13], Bae [14] on accuracy (97.08 / 97.30 / 95.96 / 98.65) and F1.

**Stated future work:** "add more functionality features" and "increase the accuracy without degrading security." Deliberately vague — which is good news for us: the real gaps are elsewhere and they are large.

---

## 2. The concrete problems — this is where the project lives

These are not stylistic complaints. Each one is a specific, checkable defect with a specific fix.

### P1. The evaluation inverts the class prior, which makes the headline number meaningless

The paper states plainly: *"For the performance comparison, we have taken 90% attackers (ransomware) and 10% benign samples."*

BitcoinHeist actually contains **41,413 ransomware and 2,875,284 legitimate transactions — a 1.42% positive rate**. The paper evaluates at a 90% positive rate, a **63× inflation of the base rate**. At 90% prevalence, a classifier that outputs "ransomware" unconditionally scores 90% accuracy and F1 = 0.947 — i.e. the reported 98.98% / 0.990 is measured against a trivial baseline of 0.947, not 0.5. The paper even acknowledges this in one sentence ("it may cause more false positive rates") and moves on.

**What this means for a hospital:** at the true 1.42% prevalence, a detector with a 2% FPR raises ~57,500 false alarms per 2.9M transactions against ~41k true ones — precision below 42%. None of this is visible in the paper's numbers.

### P2. The classifier detects *payments*, not *ransomware*

BitcoinHeist features are `address, year, day, length, weight, count, looped, neighbors, income, label`. These are **Bitcoin address-graph features of a ransom payment**. A model trained on them cannot detect ransomware executing on a hospital workstation — the payment happens *after* encryption, after the damage. Yet the framework's Phase 3 is presented as the live detection module feeding Phase 4 mitigation. There is a genuine architectural mismatch between what is claimed (detect + mitigate on the device) and what is evaluated (post-hoc classification of on-chain payment addresses).

### P3. Every one of those features is attacker-controllable

`count`, `looped`, `neighbors`, `income`, `weight`, `length` are all functions of how the attacker structures the payment graph. Splitting a ransom across k addresses, inserting peel-chain hops, or adding decoy neighbors changes all of them at negligible cost. There is **no adversarial evaluation whatsoever**. A classifier whose features the adversary can freely edit for ~$1 in transaction fees is not a defence.

### P4. The blockchain and the ML are never coupled in the evaluation

The blockchain measurements (TPS, computation time) and the ML measurements (accuracy, F1) are reported in separate subsections and never combined. No end-to-end number exists for the thing that actually matters: **how long from first malicious file write to mitigation trigger**, given that a detection must be written to `BC_SigRW`, mined under PBFT, and propagated to `CS_l`. At 115–222 TPS with 100-transaction blocks, a block takes ~0.45–0.87 s just to fill; LockBit-class ransomware encrypts thousands of files in that window.

### P5. The backup blockchain, as described, cannot store healthcare data

Algorithm 1 puts data backups `DT_BU` into blockchain transactions. A single CT study is 100–500 MB. Replicating that across miner nodes in an append-only ledger is not implementable. The paper never reports storage overhead, block size, or recovery time — only mining time for 100-transaction blocks of unspecified payload.

### P6. Baseline comparison is apples-to-oranges

Almashhadani (network traffic of Locky), Hwang (dynamic analysis, 2-stage), Sharmeen (deep learning on API/permission features), and Bae (opcode/API features) each use **different datasets and different input modalities**. Comparing their accuracies to a BitcoinHeist address classifier is not a comparison. No common-dataset reimplementation is done.

### P7. PBFT security claims are asserted, not measured

Four miner nodes ⇒ PBFT tolerates f = 1. The Sybil discussion ("deploy PBFT along with PoW") is hand-waved and contradictory (PoW in a *private permissioned* chain defeats the point). No experiment varies n or f.

---

## 3. Proposed contribution — pick a spine, then add satellites

**Recommended spine (the one I'd defend in a viva): _"BSFR-SH under an honest threat model: base-rate-correct evaluation, a host-behaviour detection tier, and adversarial payment-graph evasion."_**

That single sentence covers P1, P2, P3 and produces results that are guaranteed to be non-trivial and quantitative — you cannot fail to get a finding, because either the original numbers survive (surprising, publishable) or they collapse (expected, and you then fix it).

### Improvement A — Honest re-evaluation of the detection module *(mandatory, ~2 weeks)*

Concrete steps:
1. Rebuild the BitcoinHeist pipeline at the **natural 1.42% prevalence**, not 90/10.
2. Replace accuracy/F1 with **PR-AUC, precision@recall=0.9, MCC, and alerts-per-day at a fixed detection rate**. Report a full precision–recall curve, not a single operating point.
3. Replace the random split with a **temporal split**: BitcoinHeist carries `year` and `day`. Train on 2011–2016, test on 2017–2018. Random splitting on a time-series dataset leaks future information into training — this alone typically costs several points.
4. Handle the **positive-unlabeled** problem: the "white" label means *not known to be ransomware*, not *benign*. Rerun with a PU-learning estimator (e.g. Elkan–Noto) and report how the estimated true positive rate shifts.
5. Deduplicate: BitcoinHeist has many addresses appearing across days; group-aware splitting by address prevents the same address landing in both train and test.

**Expected deliverable:** a table showing the paper's 98.98% / 0.990 alongside your leakage-free, base-rate-correct numbers. My prediction: PR-AUC in the 0.3–0.6 range under temporal split. That gap *is* the contribution.

### Improvement B — Add the missing host-behaviour tier *(the architectural fix, ~3 weeks)*

Make BSFR-SH actually detect ransomware on the endpoint, then use the on-chain payment classifier for what it's good at — *attribution and family labelling*, not detection.

- **Tier 1 (host):** behavioural features from file-system/API traces — write-entropy per file (Shannon entropy of written blocks: encrypted output ≈ 7.99 bits/byte vs ~4–6 for documents), rename-to-new-extension rate, directory traversal breadth, `CryptEncrypt`/`BCryptEncrypt` API n-grams, MFT/shadow-copy deletion (`vssadmin delete shadows`). Data sources: the **Ransomware-PE / Elderan API-call dataset**, **VirusShare/MalwareBazaar** samples run in a Cuckoo/CAPE sandbox, or a synthetic I/O trace generator you write yourself against a corpus of documents.
- **Tier 2 (chain):** the existing BitcoinHeist classifier, repositioned as a family attributor.
- **Fusion:** Tier 1 raises the alert and triggers Phase 4 mitigation; Tier 2 enriches the on-chain signature record `Sig_RW`.

This directly instantiates what the paper *claims* Phase 2 does ("honeypot systems can be deployed") but never implements.

### Improvement C — Adversarial payment-graph evasion *(the sharpest result, ~2 weeks)*

Implement three attacker strategies against the on-chain classifier, all realisable on mainnet:
1. **Payment splitting** — ransom split over k ∈ {2,4,8,16} addresses (changes `count`, `income`, `neighbors`)
2. **Peel-chain padding** — insert h ∈ {1,3,5} hop-through addresses (changes `length`, `looped`)
3. **Decoy mixing** — add benign-looking co-spends (changes `weight`, `neighbors`)

Measure detection rate vs. attacker cost in satoshis. Then defend: retrain with **adversarial augmentation** over the same transformation family, and/or design features **invariant to splitting** (e.g. aggregate over the transitive closure of the payment cluster rather than per-address). Report the robust-accuracy/clean-accuracy tradeoff.

### Improvement D — Real end-to-end latency on a real ledger *(engineering depth, ~2 weeks)*

Reimplement the two chains on **Hyperledger Fabric** (permissioned, PBFT-family ordering via Raft/BFT-SMaRt, chaincode in Go or Node):
- Chaincode 1: `SignatureRegistry` — `PutSignature(hash, features, family)`, `QuerySignature(hash)`
- Chaincode 2: `BackupIndex` — Merkle root + version pointer per backup snapshot (**data off-chain**, see E)

Measure the metric the paper is missing: **window of exposure** = time from first malicious write → detection → block commit → mitigation ACK at the endpoint. Sweep endorsement policy (1-of-3, 2-of-3, 3-of-5), block size, and batch timeout. Convert to the number that a hospital CISO cares about: **files encrypted during the window**, using a measured encryption rate from your Tier-1 sandbox runs.

### Improvement E — Make backup/recovery implementable and measure RPO/RTO *(~1.5 weeks)*

Replace "store backups as transactions" with **off-chain content-addressed storage + on-chain Merkle commitment**:
- Chunk with content-defined chunking (FastCDC), dedupe, store in IPFS or MinIO
- On-chain: `{snapshot_id, merkle_root, timestamp, prev_snapshot}` — ~200 bytes/snapshot instead of gigabytes
- Add an explicit **rollback-attack defence**: the chain is append-only, so an attacker who encrypts *and waits* cannot silently poison all snapshots; quantify the retention depth needed as a function of ransomware dwell time.

Deliverable: **RPO/RTO curves vs. storage overhead** — e.g. "5-minute RPO on a 1 TB EHR store costs 3.2× raw storage with dedup; recovery of a 50 GB department completes in 11 min."

### Improvement F — Consensus scaling *(cheap, ~0.5 week)*

Sweep n ∈ {4, 7, 10, 13, 16} miner nodes, measure TPS and commit latency, crash f and f+1 nodes, show the liveness cliff. Replaces the paper's asserted Sybil/51% claims with a measured graph.

### Scope control

Do **A + C + D** for a compact, sharp project. Do **A + B + C + D + E** for an ambitious one. F is a half-week filler that makes the evaluation section look complete. Don't attempt all six unless you have a partner.

---

## 4. Rough timeline (14 weeks)

| Week | Work | Checkpoint artefact |
|---|---|---|
| 1 | Read BSFR-SH + Akcora et al. (BitcoinHeist, IJCAI'20). Get the UCI dataset. Reproduce the paper's *own* 90/10 setup exactly. | `repro_baseline.ipynb` reproducing ~98.9% |
| 2 | Honest re-evaluation: natural prevalence, temporal split, address-grouped CV, PU handling. PR curves. | **Result R1:** honest-vs-reported table |
| 3 | Set up Fabric test network (3 orgs, 2 peers each). Write `SignatureRegistry` chaincode. | Chaincode deployed, tx working |
| 4 | Sandbox pipeline for Tier 1: run 30–50 ransomware samples + 50 benign apps in CAPE/Cuckoo, extract I/O + API traces. *(If sample handling is restricted, use the Elderan/API-call dataset instead — decide this in week 1.)* | Feature-extraction script + labelled trace set |
| 5 | Train Tier-1 behavioural detector. Entropy/rename/API-ngram features. Time-to-detection (files lost before alert). | **Result R2:** Tier-1 detection curve |
| 6 | Adversarial payment-graph transformations; measure degradation of Tier-2. | **Result R3:** robustness-vs-cost plot |
| 7 | **Mid-semester review.** Adversarial training / split-invariant features; re-measure. Write up R1–R3. | Mid-sem report + demo |
| 8 | `BackupIndex` chaincode + off-chain CDC/dedup store. | Backup/restore working end to end |
| 9 | End-to-end window-of-exposure instrumentation; sweep endorsement policy & block params. | **Result R4:** latency breakdown |
| 10 | RPO/RTO vs storage overhead sweep. | **Result R5:** RPO/RTO curves |
| 11 | Consensus scaling sweep (n, f); crash-fault liveness. | **Result R6** |
| 12 | Integration: full demo — infect a VM, detect, commit signature, mitigate, restore from snapshot. Record video. | Working demo |
| 13 | Full write-up: paper-style report with honest comparison table vs original BSFR-SH. | Draft report |
| 14 | Polish, reproducibility package, final presentation. | Final deliverables |

Buffer note: weeks 4–5 (malware sandboxing) carry the highest risk. Decide by end of week 1 whether you get live-sample permission; if not, commit to the public API-call dataset and reclaim a week.

---

## 5. Expected deliverables

1. **Code repository** — `bsfr-sh-plus/` with `detection/` (Tier 1 + Tier 2), `chaincode/` (Fabric Go chaincode), `backup/` (CDC + Merkle commitment), `adversarial/` (payment-graph transforms), `eval/` (all figures reproducible via `make figures`).
2. **Reproduction baseline** — a notebook reproducing the paper's reported 98.98%/0.990 under its own 90/10 protocol. This proves your critique is not an implementation error on your part. **Do not skip this.**
3. **Six results**, each a figure or table:
   - R1 honest re-evaluation (PR-AUC, precision@recall, temporal split)
   - R2 host-behaviour tier detection latency (files encrypted before alert)
   - R3 adversarial evasion rate vs attacker cost
   - R4 end-to-end window of exposure vs ledger configuration
   - R5 RPO/RTO vs storage overhead
   - R6 consensus throughput/latency vs n and f
4. **Threat-model document** — explicit adversary capabilities (endpoint, network, miner insider, on-chain), stating precisely which BSFR-SH claims survive and which do not.
5. **Demo video / live demo** — VM infected in a sandbox, Tier-1 alert fires, signature committed on Fabric, mitigation triggered, data restored from off-chain snapshot with on-chain Merkle verification.
6. **Report (10–14 pages, IEEE format)** with a comparison table: *BSFR-SH as reported* vs *BSFR-SH reproduced* vs *BSFR-SH++ (ours)* across accuracy, PR-AUC, adversarial robustness, end-to-end latency, RPO/RTO.

---

## 6. Tools, data, and prerequisites

- **Data:** BitcoinHeist (UCI ML Repository, 2.9M rows, ~500 MB CSV); Elderan API-call ransomware dataset or MalwareBazaar samples; any document corpus for synthetic encryption traces.
- **Blockchain:** Hyperledger Fabric 2.5 (test-network), Go chaincode. *(Alternative: a Ganache/Solidity setup is easier but permissionless-EVM semantics fit the paper's private-chain model poorly — prefer Fabric.)*
- **ML:** scikit-learn, XGBoost, `imbalanced-learn`; SHAP for feature attribution.
- **Sandbox:** CAPEv2 or Cuckoo in an isolated VM with host-only networking, snapshots, no internet egress. **Handle live samples only with your advisor's explicit approval and on an air-gapped/host-only VM.**
- **Storage:** MinIO or IPFS (kubo) + FastCDC implementation.

---

## 7. Risks and how to defuse them

| Risk | Mitigation |
|---|---|
| Live ransomware samples not permitted | Fall back to public API-call/I-O-trace datasets; decide in week 1 |
| Fabric setup eats time | Use `fabric-samples/test-network` as-is; only write chaincode, don't build a network from scratch |
| Honest re-evaluation "just" shows numbers drop — feels negative | Frame as the contribution: pair every drop with a fix (adversarial training, split-invariant features, host tier). Negative results plus a repair is a stronger project than a fresh 99% claim |
| Scope creep across six improvements | Freeze scope at end of week 2: A + C + D mandatory, B/E/F optional |

---

## 8. Why this satisfies "must improve the work"

You are not re-implementing BSFR-SH. You are: (i) showing its headline metric is an artefact of a 63× inflated base rate and a leaky split, (ii) showing its features are adversary-editable and fixing that, (iii) adding the endpoint detection tier the architecture requires but never implements, (iv) supplying the end-to-end latency and RPO/RTO measurements the paper omits, and (v) making the backup design implementable. Every one of those is a delta with a number attached.
