# Choosing among P12, P13, P14, P16, P19 — comparison and recommendation

One detailed brief exists per project. This document is for the decision.

---

## The one-line pitch for each

| # | Paper | The improvement, in one sentence |
|---|---|---|
| **P12** | BSFR-SH (blockchain + ransomware, IEEE TCE 2023) | The 98.98% accuracy comes from evaluating at a 90% ransomware base rate when the true rate is 1.42%; fix the evaluation, add the endpoint detection tier the architecture claims but never implements, and show the payment-graph features are adversary-editable. |
| **P13** | PPSEB (lattice PEKS on blockchain, SCN 2022) | The flagship "postquantum ⇒ KGA-resistant" claim is a category error — build the keyword-guessing attack, fix it with a lattice PAEKS construction, and replace the unimplemented (and infeasible) on-chain search with verifiable off-chain search. |
| **P14** | QPASE (lattice PASE, IEEE TIFS 2024) | The authors state communication cost as their limitation; measure it properly for the first time (real networks, real devices), then cut it via seed expansion, coefficient compression, and a Module-LWE TOPRF, re-validating security at each step. |
| **P16** | Hybrid ensemble APT detection (CCPE 2023) | SMOTE is applied before the train/test split — pure leakage; fix the protocol, show the "hybrid" gain over Random Forest is statistically insignificant, then build a sequence/graph detector that models campaigns and generate the real APT dataset the authors name as missing. |
| **P19** | Two-phase MPC-FL (CCGRID 2020) | The committee election has no manipulation resistance, so a coalition of 3 captures the committee and the privacy guarantee becomes vacuous; replace it with VRF sortition + t-of-m threshold with a derived collusion bound, add MPC-compatible robust aggregation and dropout tolerance. |

---

## Difficulty, risk, and fit

| | Background needed | Difficulty | Implementation risk | Chance of a clean, publishable result |
|---|---|---|---|---|
| **P12** | ML + blockchain (Fabric) + some malware handling | Medium | Medium (malware sandbox permissions) | High — the base-rate flaw is undeniable |
| **P13** | **Lattice crypto (heavy)** — GPV sampling, trapdoors | **Hardest** | **High** — `SamplePre`/`NewBasisDel` can eat 3 weeks | High if you clear the implementation hurdle |
| **P14** | Lattice crypto + threshold protocols + network measurement | Hard | Medium-high | Very high — but it's *extension*, not refutation |
| **P16** | ML engineering + networking. **No crypto.** | **Easiest** | Low | **Very high** — leakage is trivially demonstrable |
| **P19** | Distributed systems + applied crypto (no lattices) | Medium | Medium | High — the election attack is easy to demonstrate |

---

## Recommendation

**If you want the highest chance of an excellent grade with controllable risk: P16 (APT detection).**

The SMOTE-before-split leakage is a hard, demonstrable fact you can prove in week 3, and the fix path is rich: campaign-level modelling, a lab-generated APT dataset that directly executes the authors' own stated future work, adversarial evasion, and MITRE ATT&CK-mapped evaluation. No cryptography, no exotic libraries, no permission bottlenecks. The risk of getting stuck is the lowest of the five, and the ceiling is still high — a released, stage-annotated APT dataset is a genuine artefact other people can use.

**If you want the most intellectually serious project and you are comfortable with cryptography: P19 (MPC-FL), not P13 or P14.**

P19 gives you a real security break (the election is manipulable and the privacy guarantee collapses under a 3-party coalition) plus a genuinely open research problem (robust aggregation under secret sharing) without requiring you to implement Gaussian lattice sampling. It sits at the right difficulty for a semester: hard enough to be interesting, tractable enough to finish.

**If you specifically want a post-quantum cryptography project: P13 over P14.**

P13 has an attackable claim — you can *break* something and then *fix* it, which makes for a far more compelling report than an optimisation study. P14 is the better paper, which paradoxically makes it the harder project: you must contribute deployability engineering rather than a correction, and its authors have already thought carefully about most things. Choose P14 only if you have prior lattice-crypto implementation experience.

**P12** is a reasonable middle choice if blockchain specifically interests you — the base-rate critique is as clean as P16's leakage critique — but the ransomware-sample handling adds an approval dependency you don't control.

---

## Decision questions

1. **Do you want to write cryptographic code?** No → P16 or P12. Yes, but not lattices → P19. Yes, lattices → P13.
2. **Do you have a partner?** Alone → P16 or P19. Two people → any, including P13/P14.
3. **Do you have GPU/VM resources for a small lab?** Yes → P16 becomes much stronger (Caldera emulation). No → P19 or P12.
4. **Do you prefer refuting or extending?** Refute-then-repair → P16, P12, P19, P13. Extend a solid paper → P14.

---

## Common structure across all five briefs

Each brief follows the same shape, so they're directly comparable:

1. What the paper actually does — with the specific parameters, algorithms, and numbers, so you can check my critique against the source
2. The concrete problems — each one a specific, checkable defect, not a generic complaint
3. Proposed contribution — a recommended "spine" plus optional satellite improvements, each with a time estimate and scope-control guidance
4. A 14-week timeline with a named checkpoint artefact per week and an explicit mid-semester review at week 7
5. Expected deliverables — repository structure, results list, report, demo
6. Tools, data, prerequisites — with fallbacks for anything that needs credentials or approvals
7. Risks and mitigations
8. Why it satisfies "must improve the work" — the explicit argument you'd make to your instructor

---

## One piece of general advice

**In every one of these projects, week 2–3 is a faithful reproduction of the original paper's own protocol, flaws included.** Do not skip this. It is what separates "the paper is wrong" from "I couldn't reproduce it," and it is the difference between a critique your examiner accepts and one they don't. It also gives you a guaranteed deliverable by week 3 no matter how the rest of the project goes.
