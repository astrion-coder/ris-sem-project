# P16 — Anomaly Detection Using Machine Learning for Advanced Persistent Threats (APT)

**Paper:** N. Saini, V. B. Kasaragod, K. Prakasha, A. K. Das, "A hybrid ensemble machine learning model for detecting APT attacks based on network behavior anomaly detection," *Concurrency and Computation: Practice and Experience*, 35(28), 2023. DOI 10.1002/cpe.7865

---

## 1. What the paper actually does

**Pipeline:**
1. **Datasets:** CSE-CIC-IDS2018, CIC-IDS2017, NSL-KDD, UNSW-NB15
2. **Sampling:** stratified random sampling with **`frac = 0.002`** per CSV on CSE-CIC-IDS2018 (i.e. 0.2% of ~1M records per file, ≈2,000 rows per file), justified by compute cost
3. **Label collapse:** all attack classes merged into a single "anomaly" class → binary classification
4. **Balancing:** **SMOTETomek** (SMOTE oversampling + Tomek-link undersampling)
5. **Feature selection:** Pearson correlation + Information Gain → **30 features out of 80**; SHAP used for post-hoc importance
6. **Split:** 70:30 train/test via `sklearn`, with the 70% further split 80:20
7. **Model:** `SimpleClassifierAggregator` over `RandomForestClassifier` + `XGBClassifier`, combined by **"average" aggregation**

**Results:** 98.92% (CSE-CIC-IDS2018), 99.91% (CIC-IDS2017), 99.24% (NSL-KDD), 97.11% (UNSW-NB15). AUC 98.91% on IDS2018; hybrid FPR 0.52% vs RF 0.40% vs KNN 1.42%. Test set on IDS2018 = 15,583 rows (TP 7,631, TN 7,783).

**The authors' own admission, in the paper:** *"no real latest APT attack samples are being used"* — the four datasets contain no genuine APT traffic. Their stated future work: combine ML with DL, and build a dataset with current attack behaviour.

---

## 2. The concrete problems

### P1. SMOTE is applied **before** the train/test split — this is textbook data leakage

The paper's ordering is explicit: SMOTETomek is described first, then *"After converting it into balanced dataset, the CSE-CIC-IDS2018 dataset has been divided into two parts: training and testing... with a 70:30 ratio."*

SMOTE generates synthetic minority samples by interpolating between a point and its *k* nearest neighbours **across the whole dataset**. Splitting afterwards places synthetic points in the test set whose parents are in the training set — the model is effectively evaluated on interpolations of its own training data. In the intrusion-detection literature this inflates reported accuracy by a well-documented margin, and it is the most likely single explanation for 99.91% on CIC-IDS2017.

**This is a decisive, easily demonstrable flaw. Fixing it is the spine of the project.**

### P2. The "hybrid" is an average of two correlated tree ensembles, and the gain is within noise

RF (bagged trees) and XGBoost (boosted trees) are both axis-aligned tree ensembles on the same 30 features. Their errors are highly correlated, so simple probability averaging cannot buy much — and indeed the reported gains are: IDS2018 98.92 vs RF 98.65 (**+0.27**), CIC-IDS2017 99.91 vs 99.88 (**+0.03**), NSL-KDD 99.24 vs 99.15 (**+0.09**), UNSW-NB15 97.11 vs 96.98 (**+0.13**).

On a 15,583-row test set, a 0.27 pp difference is ~42 samples. **No confidence intervals, no repeated runs, no significance test, no variance across seeds are reported anywhere.** The central claim — that the hybrid beats its components — is not statistically supported. The paper's own FPR table even shows RF *beating* the hybrid (0.40% vs 0.52%).

### P3. `frac = 0.002` throws away 99.8% of the data, then claims generalisation

CSE-CIC-IDS2018 has ~16M flows. The paper trains and tests on a few thousand. Rare-but-critical classes are decimated: 02-22-2018 contains 34 SQL-injection records total — at `frac=0.002` the expected count in the sample is **0.068**, i.e. the class effectively disappears. Yet the paper claims to "successfully detect and classify APT attacks on all datasets."

### P4. Merging all attacks into one class destroys the APT problem

APT is defined by being **multi-stage, low-and-slow, and stealthy**. Collapsing DDoS-HOIC (686,012 records on 02-21) and SQL injection (34 records) into one "anomaly" label means the classifier is overwhelmingly learning to detect volumetric DoS — the *opposite* of APT behaviour. A model scoring 98.9% on this label is mostly detecting flooding.

### P5. Per-flow classification cannot detect an APT campaign

The datasets are per-flow feature vectors (CICFlowMeter, 80 features). APT detection requires correlating events **across hosts and across weeks** — beaconing periodicity, lateral movement graphs, staged exfiltration. A per-flow i.i.d. classifier has no mechanism for any of this. The paper's title claims "network behavior anomaly detection" but the method has no notion of behaviour over time.

### P6. Random split on time-ordered network traffic

CIC-IDS2017 and CSE-CIC-IDS2018 are captured over consecutive days with distinct attacks per day. Random shuffling puts flows from the same attack burst — often the same TCP session — in both train and test. Any realistic deployment trains on the past and tests on the future.

### P7. No adversarial or evasion evaluation

Network-flow features (packet sizes, inter-arrival times, flow duration) are adversary-controllable through padding and timing jitter. No evasion analysis exists.

### P8. Comparison table (Table 11) compares across different datasets and protocols

Reported baselines use different splits, different sampling, different preprocessing. Nothing is reimplemented under a common protocol.

---

## 3. Proposed contribution

**Recommended spine: _"An honest benchmark for APT detection: leakage-free evaluation, a sequence/graph-level detector that actually models campaign behaviour, and evaluation on real multi-stage attack data."_**

This is the most accessible of the five projects (no cryptography needed) and the one where you are most certain to produce clear, defensible results.

### Improvement A — Leakage-free re-evaluation *(mandatory, ~2.5 weeks)*

1. **Reproduce the paper's protocol exactly**, including SMOTE-before-split, and confirm you get ~98.9/99.9/99.2/97.1. This proves your critique is not an implementation artefact.
2. **Fix the pipeline** and measure the drop, ablating one flaw at a time so each is separately attributable:
   - SMOTE inside a `sklearn.Pipeline` applied **only to training folds** (use `imblearn.pipeline.Pipeline`, which is exactly what this exists for)
   - **Group-aware splitting** by source IP / flow session, so the same session cannot straddle the split
   - **Temporal split** — train on earlier capture days, test on later ones
   - Full data instead of `frac=0.002`; if compute-bound, sample at `frac=0.05` and show the sensitivity curve
3. **Report properly:** PR-AUC and MCC (not accuracy) at the *natural* class ratio, with **5×2 cross-validation, mean ± std over ≥10 seeds**, and a **McNemar test** for hybrid-vs-RF. Settle P2 with statistics rather than a single decimal.

**Expected finding:** a large drop on CIC-IDS2017/2018 and hybrid-vs-RF collapsing into statistical noise. This is your headline table.

### Improvement B — A detector that models the campaign, not the flow *(the core contribution, ~4 weeks)*

Replace per-flow i.i.d. classification with something that can express APT structure. Build **two** levels so you can show what each buys:

**B1. Host-session sequence model.** Aggregate flows into per-(host, time-window) sequences. Features per window: connection counts, unique destination ports/IPs, byte-ratio in/out, **beaconing score** (periodicity via the coefficient of variation of inter-arrival times, or autocorrelation peak of the connection timeseries), DNS query entropy, and long-connection counts. Model with a temporal architecture — **TCN or a small Transformer encoder** (both train fast on CPU/one GPU; avoid a heavy LSTM stack).

**B2. Graph-level lateral-movement detection.** Build a host-communication graph per time window (nodes = hosts, edges = flows with volume/port attributes). Train a **GNN (GraphSAGE or GAT)** for node-level anomaly scoring, or use a simpler, very defensible baseline: an **anomaly score on graph statistics** (new-edge rate, degree change, connected-component churn). Lateral movement shows up as edges that never existed before between hosts that shouldn't talk.

**B3. Kill-chain–aware evaluation.** Instead of one merged "anomaly" label, evaluate per APT stage — reconnaissance, initial access, lateral movement, exfiltration — mapped to **MITRE ATT&CK** tactics. Report **per-stage detection rate** and **time-to-detect (in windows) from campaign start**. That metric is what an SOC cares about and it appears nowhere in the paper.

### Improvement C — Evaluate on data that actually contains APT behaviour *(fixes the paper's own stated gap, ~2.5 weeks)*

The authors say no real APT samples exist in their datasets and name dataset construction as future work. Do it — you have three tractable options, and you should use at least two:

1. **DARPA OpTC** (Operationally Transparent Cyber) — real multi-day red-team campaigns with host telemetry across ~1,000 hosts. Large but public.
2. **DARPA Transparent Computing (E3/E5)** — provenance graphs with APT-style engagements; the standard benchmark in the provenance-detection literature (used by UNICORN, THREATRACE, ATLAS).
3. **Build your own with Caldera + Atomic Red Team.** MITRE **Caldera** runs scripted adversary emulation (APT29/APT3 profiles) in a small VM lab; capture with Zeek/Suricata + Sysmon, generate flows with CICFlowMeter for comparability with the original paper. This is very achievable: 4–6 VMs, a week of setup, and you get **ground-truth-labelled, stage-annotated APT traffic** that the paper explicitly lacks.

**Deliverable:** cross-dataset generalisation — train on CIC-IDS2018, test on your Caldera/OpTC APT data. My prediction is a catastrophic drop, which quantifies exactly how much the paper's 98.9% means for real APTs.

### Improvement D — Adversarial evasion of flow features *(~1.5 weeks)*

Implement constrained evasion respecting network semantics (you can pad packets and add delay; you cannot make bytes negative or violate protocol):
- **Packet padding** to shift size distributions
- **Timing jitter / deliberate slow-down** — the defining APT behaviour
- **Flow splitting** across ports/sessions

Measure detection rate vs. evasion budget (added bytes, added latency). Then defend with adversarial training or feature ablation, and report the robust/clean tradeoff. Bonus: show that jitter evasion is *exactly* what the low-and-slow APT threat model predicts, tying the result back to the problem definition.

### Improvement E — Deployability *(cheap, ~1 week)*

The paper claims the model is "computationally simple" but reports no inference cost. Measure throughput (flows/sec), model size, and per-window latency for each detector; report on a commodity CPU. Add a **cost-sensitive operating point** analysis: given an SOC that can triage *k* alerts/day, which model maximises true campaigns caught?

### Scope control

**A + B1 + C** is the minimum coherent project. Add **B2** for depth or **D** for sharpness. E is a one-week finisher. Doing A + B + C + D + E is feasible for two people, tight for one.

---

## 4. Rough timeline (14 weeks)

| Week | Work | Checkpoint artefact |
|---|---|---|
| 1 | Read the paper + Engelen et al. "Troubleshooting an IDS dataset" (CIC-IDS2017 label errors) + Arp et al. "Dos and Don'ts of ML in Security". Download all four datasets. | Reading notes; data staged |
| 2 | Faithful reproduction of the paper's exact pipeline including SMOTE-before-split. | **Result R0:** ~98.9/99.9/99.2/97.1 reproduced |
| 3 | Ablate the flaws one at a time: SMOTE-in-pipeline → group split → temporal split → full data. 10 seeds, CIs, McNemar. | **Result R1:** the honest table |
| 4 | Build the flow→window→host aggregation layer; beaconing and periodicity features. | Feature pipeline + EDA plots |
| 5 | B1: TCN/Transformer sequence detector. Compare against the flow-level hybrid on identical splits. | **Result R2:** sequence vs flow |
| 6 | Stand up the Caldera lab (4–6 VMs, Zeek + Sysmon + CICFlowMeter). Run APT29 emulation profile. | Lab operational; first capture |
| 7 | **Mid-semester review.** Label and stage-annotate the captured campaigns against MITRE ATT&CK. | Mid-sem report + labelled dataset v1 |
| 8 | Cross-dataset evaluation: train on IDS2018 → test on Caldera/OpTC. Both directions. | **Result R3:** generalisation collapse |
| 9 | B2: host-graph construction + GNN or graph-statistics anomaly scoring for lateral movement. | **Result R4:** lateral-movement detection |
| 10 | B3: per-stage detection rate + time-to-detect from campaign start. | **Result R5:** kill-chain metrics |
| 11 | D: adversarial evasion (padding, jitter, splitting) + adversarial training defence. | **Result R6:** robustness curves |
| 12 | E: throughput/latency/model-size + alert-budget analysis. Integration and final runs. | **Result R7** |
| 13 | Write-up; release the emulated APT dataset with documentation. | Draft report + dataset card |
| 14 | Polish, reproducibility package (`make all` regenerates every figure), presentation. | Final deliverables |

The Caldera lab (week 6) is the schedule risk — if VM resources are tight, fall back to DARPA OpTC, which needs only disk and patience.

---

## 5. Expected deliverables

1. **`apt-honest-bench/` repository**
   - `repro/` — faithful reproduction of the published pipeline
   - `pipeline/` — leakage-free pipeline with configurable ablations
   - `models/` — flow-level hybrid, TCN/Transformer sequence model, graph model
   - `lab/` — Caldera scenario files, Zeek/Sysmon configs, capture and labelling scripts
   - `adversarial/` — evasion transforms
   - `eval/` — `make figures` regenerates everything
2. **A released, stage-annotated APT dataset** from your emulation lab, with a dataset card documenting topology, ATT&CK techniques exercised, capture duration, and label semantics. **This alone is a real contribution** — it directly executes the future work the authors named, and other students can use it.
3. **The honest results table** — published numbers vs faithful reproduction vs each ablation (SMOTE-in-pipeline, group split, temporal split, full data), with mean ± std over 10 seeds and significance tests. Include the McNemar result for hybrid-vs-RF.
4. **Seven results:** R0 reproduction, R1 leakage-free re-evaluation, R2 sequence vs flow, R3 cross-dataset generalisation, R4 lateral movement, R5 per-stage detection + time-to-detect, R6 adversarial robustness, R7 deployability.
5. **Report (12–16 pages, IEEE format)** structured as: what the paper claims → what survives an honest protocol → what a campaign-aware detector recovers → what real APT data shows.
6. **Demo:** live Caldera APT29 emulation in the lab with the detector raising staged alerts mapped to ATT&CK techniques as the campaign progresses.

---

## 6. Tools, data, prerequisites

- **Datasets:** CSE-CIC-IDS2018 and CIC-IDS2017 (UNB CIC, free registration), NSL-KDD, UNSW-NB15; DARPA OpTC (public S3); DARPA TC E3/E5.
- **Emulation:** MITRE **Caldera**, **Atomic Red Team**, 4–6 VMs (VirtualBox/Proxmox/ESXi), Windows victims + Linux C2.
- **Capture:** Zeek, Suricata, Sysmon (with SwiftOnSecurity config), CICFlowMeter (for feature comparability with the paper).
- **ML:** scikit-learn, XGBoost, `imbalanced-learn` (note: use `imblearn.pipeline.Pipeline`, not `sklearn`'s — this is the actual fix for P1), PyTorch, PyTorch Geometric or DGL, SHAP.
- **Background needed:** solid ML engineering and networking basics. **No cryptography.** If your strength is systems/ML rather than theory, this is the right project of the five.

---

## 7. Risks

| Risk | Mitigation |
|---|---|
| Caldera lab needs more compute than available | Use DARPA OpTC (already captured, real red team); or run a 3-VM minimal lab (attacker, pivot, target) |
| Full CSE-CIC-IDS2018 (~16M flows) too big for a laptop | Use Polars/Dask or chunked processing; run at `frac=0.05` with a sensitivity curve showing where results stabilise |
| Results are "just" negative | They are not — pair every drop with the campaign-aware detector that recovers performance on the *right* problem, plus a new dataset. Negative-result-plus-repair is the strongest form of this project |
| CIC-IDS2017 has known label errors (Engelen et al. 2021) | Cite it, use the corrected labels, and report both — this itself becomes a small contribution |

---

## 8. Why this satisfies "must improve the work"

You demonstrate that the reported accuracies rest on SMOTE-before-split leakage and a random split of time-ordered traffic; you show with proper statistics that the "hybrid" advantage over plain Random Forest is not significant; you replace per-flow classification with a sequence/graph detector that can express the multi-stage, low-and-slow behaviour that defines an APT; you build and release the real APT dataset the authors themselves named as the missing piece; and you add adversarial and deployability evaluations that do not exist in the original. Every one is a concrete, measurable delta.
