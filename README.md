# QPASE in Python

This repository implements QPASE from Jiang and Wang, "QPASE: Quantum-Resistant Password-Authenticated
Searchable Encryption for Cloud Storage", IEEE Transactions on Information Forensics and Security, vol. 19,
2024. The paper is `QPASE_Quantum-Resistant_Password-Authenticated_Searchable_Encryption_for_Cloud_Storage.pdf`.

A user remembers only an identity and a password. A threshold of `t` out of `N` servers runs a lattice
TOPRF on the password, from which the user derives a key `K_u`, a Dilithium key pair and one search key
`dsk` per keyword. The user stores encrypted documents with an encrypted keyword index on any server.
To search, the user sends `dsk` to every server. Each server returns the items whose index matches,
and only the user can decrypt them. The code follows the paper's Sections II and IV and Figs. 1, 2, 5
and 6. Where the paper is incomplete or inconsistent, the choice made is listed in
[Where this differs from the paper](#where-this-differs-from-the-paper).

The design and every decision behind it are in `docs/implementation-plan.md`.

## Module map

Everything lives in `src/ris_sem_project/`. The notebooks only call these modules.

- `params.py` holds the Table II parameter sets `PARAM_I` and `PARAM_II`, `setup()` (Setup, Sec. IV-A), and `Lattice`, which parses `pp` once.
- `primitives/ring.py` is exact arithmetic in `R_q = Z_q[X]/(X^n + 1)`.
- `primitives/sampling.py` has the uniform samplers and the discrete Gaussian `chi_sigma` (Definition 3).
- `primitives/gadget.py` is `G^{-1}`, the binary decomposition (Sec. II-B).
- `primitives/bp_prf.py` is the Banerjee-Peikert lattice PRF `F_k(x)` (Lemma 1).
- `primitives/extractor.py` is Ding's robust extractor, the hint `S` and the extractor `E` (Definition 8).
- `primitives/secret_sharing.py` has Shamir sharing over `R_q`, integer Lagrange coefficients and the DKG (Definitions 11-12).
- `primitives/toprf.py` is the variant TOPRF `Pi_TOPRF` (Figs. 1-2, Theorem 1).
- `primitives/hkdf.py` and `primitives/prf.py` are the HKDF and PRF of Setup, both built on the BP PRF (Definitions 9-10).
- `primitives/signature.py` wraps ML-DSA-44 (CRYSTALS-Dilithium) with key generation from a seed.
- `primitives/symmetric.py` wraps AES-256-GCM.
- `primitives/encoding.py` is the length-prefixed encoding of signed and encrypted tuples.
- `index.py` builds the searchable index `Ct` of one document (O1) and runs the check of R2 and R3.
- `parties/` has the abstract `User`, `Server` and adversary classes, the wire messages in `types.py`, and the concrete `QPASEUser` and `QPASEServer`.
- `protocol.py` runs whole phases (DKG, Register, Login, Outsource, Retrieve) and returns a record of every message.
- `root_attack.py` is the PARAM II offline password test shown in notebook 06.
- `display.py` formats values for the notebooks and computes nothing.

The notebooks in `notebooks/` show each phase with the data that crosses the wire:

- `01_preliminaries.ipynb` covers the building blocks of Sec. II.
- `02_register_login.ipynb` covers the DKG, Register and Login (Sec. IV-A to IV-C, Fig. 5).
- `03_outsource_retrieve.ipynb` stores real documents on the servers and searches them (Sec. IV-D and IV-E, Fig. 6).
- `06_param_ii_offline_guessing.ipynb` shows why the demos do not use PARAM II.

## Server key update

Sec. IV-F. This section is a placeholder until the key update lands.

## Run the tests

From the repository root:

```sh
.venv/bin/python -m unittest discover -s tests -v
```

## Run the notebooks

To run every notebook in `notebooks/` top to bottom in a fresh kernel and save its outputs:

```sh
.venv/bin/python scripts/run_notebooks.py
```

To run some of them, pass their paths, for example `.venv/bin/python scripts/run_notebooks.py notebooks/03_outsource_retrieve.ipynb`.
Each notebook ends with assertion cells, so a notebook that runs without error means the property it shows held.

To check every row of [Numeric claims](#numeric-claims) against the saved notebook outputs:

```sh
.venv/bin/python scripts/check_readme_claims.py
```

## Where this differs from the paper

`docs/implementation-plan.md` Part 2 explains each item.

- The scheme runs in the ring `R_q = Z_q[X]/(X^n + 1)` of Sec. II-B and Fig. 2, not with the plain-LWE matrices of Fig. 1 (decision 1).
- `q = 2^28 - 57` is not NTT-friendly, so ring products use a complex FFT on split coefficients, which is exact (decision 2).
- The TOPRF combines with the sign that the algebra of Theorem 1's proof gives, accepts only server subsets with integer Lagrange coefficients, and draws the DKG contributions, `r` and `e` from `chi_sigma` (decision 3).
- The extractor hint `sigma = S(F)` is computed at Register, stored by every server and returned at Login, so the same password gives the same `K_u` (decision 4). Fig. 2 computes the hint from a different value.
- DKG sharing polynomials have degree `t - 1`, so any `t` servers can run Login (decision 5).
- Key-update commitments use a linear hash `H(x) = A_H x mod q`, because the check in Sec. IV-F needs a homomorphic `H` (decision 6).
- Values the paper leaves open are fixed as `p = 2`, `sigma = 3.2` and `L = 128`, with AES-256-GCM and ML-DSA-44 (decision 7).
- `sigma` is the standard deviation of `chi_sigma`, as the text of Definition 3 says. Its printed density would make it the width parameter.
- HKDF and the PRF use the BP lattice PRF in place of HMAC. The Dilithium seed is the start of `HKDF(K_u, "QPASE/sig")`.
- Outsource and Retrieve are authorized by `sig_Ct` and `sig_dsk` under `pk_u`, not by a passed L3. Retrieve reaches all `N` servers and Login only `t`, so an L3 gate would lock the other servers out of R2.
- PARAM II (`n = 595`) has odd ring degree, so `X = -1` is a root of `X^n + 1`. A single server can then test password guesses offline against one blinded TOPRF request. Notebooks 01 to 03 therefore run on PARAM I (`n = 512`). `notebooks/06_param_ii_offline_guessing.ipynb` shows the attack.
- The Gaussian sampler and the extractor are not constant-time. This is demonstration code.
- Multi-keyword search (Sec. IV-G) is an extension the paper sketches outside Figs. 5-6. This implementation leaves it out, and queries take one keyword.

## Numeric claims

Cell `k` is the `k`-th code cell of the notebook, which is execution count `[k]` after a fresh run with
`scripts/run_notebooks.py`. A value written `~x unit` changes between runs. The checker accepts a
printed value within a factor of 2 of it.

| Claim | Value | Notebook | Cell |
| --- | --- | --- | --- |
| Table II modulus q = 2^28 - 57 | `q = 268435399` | notebooks/01_preliminaries.ipynb | 2 |
| PARAM I ring degree | `n = 512` | notebooks/01_preliminaries.ipynb | 2 |
| PARAM II ring degree | `n = 595` | notebooks/01_preliminaries.ipynb | 2 |
| Gadget width, ceil(log2 q) | `ell = 28` | notebooks/01_preliminaries.ipynb | 2 |
| Rounding modulus of the BP PRF | `p = 2` | notebooks/01_preliminaries.ipynb | 2 |
| Standard deviation of chi_sigma | `sigma = 3.2` | notebooks/01_preliminaries.ipynb | 2 |
| Bit length of PRF and TOPRF inputs | `L = 128` | notebooks/01_preliminaries.ipynb | 2 |
| Size of each public a, a_0, a_1 | `57344 B` | notebooks/01_preliminaries.ipynb | 2 |
| Random R_q products equal to an exact integer reference | `3/3` | notebooks/01_preliminaries.ipynb | 3 |
| Output bits of one BP PRF evaluation | `14336 bits` | notebooks/01_preliminaries.ipynb | 5 |
| Median time of one BP PRF evaluation, 7 runs | `~0.6 s` | notebooks/01_preliminaries.ipynb | 6 |
| Largest TOPRF noise coefficient 2e'' in one run | `max \|2e''\| = ~5000` | notebooks/01_preliminaries.ipynb | 10 |
| q/4, the extractor's noise bound | `q/4 = 67108849` | notebooks/01_preliminaries.ipynb | 10 |
| Size of K_u and of an HKDF output | `1792 B` | notebooks/01_preliminaries.ipynb | 11 |
| Servers, threshold and attempt limit in notebook 02 | `N = 3, t = 2, mu = 14` | notebooks/02_register_login.ipynb | 2 |
| TOPRF request to each server (user id and b) | `57349 B` | notebooks/02_register_login.ipynb | 4 |
| Register TOPRF response from each server | `114688 B` | notebooks/02_register_login.ipynb | 4 |
| Size of pk_u (ML-DSA-44 public key) | `1312 B` | notebooks/02_register_login.ipynb | 5 |
| Register step 2 message (pk_u and hint) | `RegisterKeyMessage: 3109 B` | notebooks/02_register_login.ipynb | 5 |
| Login L1 response from each server | `L1 response per server: 117792 B` | notebooks/02_register_login.ipynb | 6 |
| Login L2 proof to each server | `L2 proof per server: 2457 B` | notebooks/02_register_login.ipynb | 6 |
| Repeated correct logins with byte-identical K_u | `10/10 logins gave byte-identical K_u` | notebooks/02_register_login.ipynb | 10 |
| Median time of one Login with 2 servers, 10 runs | `~2.3 s` | notebooks/02_register_login.ipynb | 10 |
| Attempt count at which S_2 refuses L1 | `mu_u = 14 reached the limit mu = 14` | notebooks/02_register_login.ipynb | 11 |
| Size of the index ciphertext Ct | `Ct 4256 B` | notebooks/03_outsource_retrieve.ipynb | 4 |
| Size of sig_Ct (ML-DSA-44 signature) | `sig_Ct 2420 B` | notebooks/03_outsource_retrieve.ipynb | 4 |
| Retrieve request to each server (user id, dsk, sig_dsk) | `RetrieveRequest, 4217 B` | notebooks/03_outsource_retrieve.ipynb | 9 |
| Time of R2 on all 3 servers, 7 stored items, 3 matches | `~1.4 s` | notebooks/03_outsource_retrieve.ipynb | 10 |
| Items recovered for the keyword medical | `recovered items [1, 3, 6]` | notebooks/03_outsource_retrieve.ipynb | 12 |
