# Prompt:

Fermilab collects a lot of data from its datacenter, petabytes, along with metadata, like IP addresses, names, emails and phone numbers of researches. That much data could be used by other data centers to study inefficiencies, bottlenecks, and optimization of massive data processing in order to optimize movements of large amounts of data and optimal distribution of compute resources, memory and IO management and distribution. It could also be used for feature engineering and training ML models. Fermilab is willing to share that data but it needs to anonymize the datasets by obfuscating sensitive information without loosing its value for compression algos, machine learning and training NN algos. The task is design an algorithm that could be used at the same time as compression of data that is efficient and can be used for processing massive amounts of data, TBytes at a batch. Please suggest best techniques and algorithms for anonymizing sensitive information along with paper references and brief explanation of the algo its advantages and cost benefit analysis.

# Answer:

1) Direct identifiers (names, emails, phone numbers, IDs)

Goal: keep linkability (same person → same token) and format (so regex, parsers, and compressors still work), while removing identity.

- Format-Preserving Encryption (FPE, FF1/FF3-1, AES-based)

How: encrypt each identifier with a secret key but keep its shape (e.g., phone “+1-312-…”, email local@domain length classes).
Why for compression: structure stays regular → Parquet dictionary/ZSTD compress well; deterministic FPE preserves joins.
When: emails, phone numbers, ID codes, user handles.
Refs: NIST SP 800-38G (FF1/FF3/FF3-1). 


- Deterministic keyed hashing (HMAC-SHA-256), optionally Base32/64-encoded
How: HMAC(key, value) → fixed pseudonym; optionally truncate for storage.
Why: very fast, stable joins across tables; great column-wise compression.
When: any string ID where preserving original format isn’t necessary.

2) Network addresses and topology signals

Goal: preserve subnet structure (critical for traffic, routing, load/flow analysis) without revealing actual IPs.

- Prefix-preserving IP pseudonymization (Crypto-PAn and successors)

How: cryptographic mapping that preserves common prefixes exactly; same /24 stays grouped after anonymization.
Why for compression/analytics: subnet patterns and flows remain meaningful; deterministic mapping improves dictionary compression.
When: IPv4/IPv6 addresses in logs, flow records, telemetry.
Refs: Crypto-PAn original/analyses and scalable variants; surveys on utility/privacy trade-offs. 


3) Quasi-identifiers in structured tables (dept, role, site, time stamps)

Goal: protect against linkage attacks while retaining statistical utility.

- k-Anonymity → ℓ-Diversity → t-Closeness (classical de-identification ladder)

How: generalize/suppress quasi-identifier columns until each released record is indistinguishable within a group (k), ensure diversity of sensitive values (ℓ), and keep group distributions close to global (t).
Why for compression: bucketization (e.g., age→bins, time→hour/day, location→region) makes columns more compressible and model-friendly.
When: publishing row-level tables for exploratory analytics; not for training highly sensitive models without DP.
Refs: Sweeney (k-anonymity), Machanavajjhala (ℓ-diversity), Li (t-closeness). 


4) Machine-learning training use-cases

Goal: train on shared data with formal privacy guarantees.

- Differential Privacy (DP) for statistics & ML
- DP-SGD for deep learning: clip per-example gradients + add calibrated noise; tracks privacy loss (ε, δ).
Trade-off: training 1.3–4× slower; small accuracy hit, but strongest formal guarantees among practical methods.
Refs: Abadi et al., “Deep Learning with Differential Privacy.” 
- Local DP for telemetry (string/value collection without trusting a curator): RAPPOR randomized response.
When: crowdsourced client metrics, feature counting, autocorrect logs.
Refs: Erlingsson et al. (RAPPOR). 
-  transfer with DP: PATE (teacher ensembles + noisy vote labels).
When: label-limited settings or when you can shard training data.
Refs: Papernot et al. (PATE; scalable PATE). 
- DP synthetic data: PrivBayes (Bayesian networks + DP marginals) for tabular releases.
When: you must publish a shareable dataset with close-to-original structure.
Refs: Zhang et al., PrivBayes. 
Foundations: “Calibrating noise to sensitivity” formalizes Laplace/Gaussian mechanisms. 


5) Cross-dataset linkage without exposing PII

Goal: allow record linkage (e.g., same user across systems) without revealing identifiers.

- Privacy-Preserving Record Linkage (PPRL) via Bloom filters

How: q-grams of names/emails hashed into Bloom filters; supports approximate matching.
Caveat: several cryptanalyses—use hardened variants (salting, composite encodings) and strict threat models.
Refs: Schnell et al. (original); later cryptanalysis & improvements; recent implementation guidance. 

## Compression-aware anonymization: how to “do both at once”

- Design a streaming, columnar pipeline that anonymizes during encode:
- Ingest → Arrow/Parquet writer with Zstandard (ZSTD).
- Per-column transforms before page encoding:
- IP columns → Crypto-PAn (prefix-preserving, AES-based). 
- Emails/phones/IDs → FPE-FF1 (same length/charset) or HMAC tokens (joinable). 
NIST Computer Security Resource Center
- Timestamps/locations → generalize (hour/day; site→region) to hit k/ℓ/t targets. 
- Free-text log lines → regex-based PII detectors for phones/emails/IPs/domains; replace spans with FPE/HMAC tokens to preserve token shapes.
- Schema registry + key mgmt (HSM/KMS) so re-processing is deterministic and revocable.
- Optional DP layer for published aggregates/training exports: add DP noise at query time (for dashboards) or train with DP-SGD/PATE on derived tables. 

### Why this compresses well:

- Deterministic pseudonyms create high-cardinality but repeatable dictionaries; FPE keeps radix/length classes, which Parquet & ZSTD exploit.
- Generalization buckets (hour/day, /16, department group) sharply lower entropy per column, boosting compression ratios while improving anonymity.
- What to use where (decision cheatsheet)
- Share raw-like logs with trusted research partners who need topology/flows: Crypto-PAn for IPs + FPE/HMAC for other identifiers; optionally t-closeness on quasi-IDs; keep joins. 
- Publish statistics or train centrally with guarantees: DP at query time or DP-SGD for models; PATE if you can shard training sets. 
- Share a “public dataset” for broad ML benchmarking: DP synthetic data (PrivBayes) with documented ε,δ (note utility drop vs. pseudonymized raw). 
- Need fuzzy linkage across silos: hardened PPRL Bloom-filter pipeline with modern mitigations.


# Unified Anonymization Approach (HMAC + FPE)

This project provides a **unified anonymization layer** for sensitive key–value metadata.  
It is designed to work on massive datasets (terabytes at batch scale) while preserving **data utility** and **compression efficiency**.

---

## Why Anonymization?

Fermilab’s telemetry and workload datasets contain both:
- **Binary blobs** of physics/particle data (not sensitive, just large).
- **Metadata** that can include sensitive personal or institutional identifiers  
  (emails, proxy subjects, accounting groups, etc.).

We need to anonymize sensitive metadata before sharing data for research, benchmarking, or ML model training — without destroying its analytical value.

---

## Two Anonymization Modes

### 1. HMAC Mode (default)
- **How it works:** Each sensitive value is run through an **HMAC-SHA-256** keyed hash.  
- **Output:** A deterministic pseudonym (Base32 string, truncated).  
- **Advantages:**  
  - Fast and scalable (hardware-accelerated).  
  - Deterministic: the same value always maps to the same token.  
  - Joins and group-bys still work.  
  - Tokens compress well (high repetition).  
- **Limitations:**  
  - Reveals *equality/linkability* (you can see that two rows came from the same subject).  
  - Does not preserve the format of the original value (e.g., looks like a random string, not an email).

### 2. FPE Mode (Format-Preserving Encryption)
- **How it works:** Values are encrypted into outputs that **look like the original** — same alphabet, same length.  
  - Example: `Alice123` → `Qtrbz482`  
  - Emails can be anonymized as `token@domain` to preserve domains.  
- **Implementation:**  
  - Uses [`pyffx`](https://pypi.org/project/pyffx/) if available (a lightweight FF1-like FPE).  
  - Falls back to a deterministic “shim” mapping: each character replaced with another from the same class (digit→digit, upper→upper, lower→lower).  
- **Advantages:**  
  - Preserves **shape and format** of data (good for downstream software expecting valid-looking inputs).  
  - More natural anonymized values (e.g., phone-number-like strings remain digit-only).  
- **Limitations:**  
  - The shim fallback is **not cryptographically strong** — good for demos, not for production-grade privacy.  
  - FPE is slower than HMAC.

---

## What is HMAC?

**HMAC (Hash-based Message Authentication Code)** is a cryptographic function that combines:
- A **secret key** (only known to the anonymization system).
- A **hash function** (here, SHA-256).

Properties:
- **Deterministic per key:** Same input + same key → same token.
- **Keyed security:** Without the secret key, you cannot invert or guess the mapping.
- **Preimage resistance:** Even with the token, it’s computationally infeasible to get the original value.

We use HMAC here as a **pseudonymization tool** — not for authentication, but because it gives us irreversible, repeatable tokens.

---

## What is FPE?

**Format-Preserving Encryption (FPE)** is an encryption technique where:
- The output looks like the input in terms of structure.
- A 16-digit credit card encrypts to another 16-digit number.
- An email encrypts to something that still looks like an email.

Why it matters:
- Some downstream systems expect specific formats.
- FPE lets us anonymize while keeping the **syntactic validity** of the data.

In this MVP:
- If `pyffx` is installed, we use it for true FPE.  
- Otherwise, we fall back to a **deterministic shim** that preserves character classes but is not cryptographically strong.

---

# New Prompt with Assignment:

1) Anon the user field and create a mapping
2) Anon the IP address field (which is expressed as a string, but can also map to a 32bit integer. yet sparsely so in our data
3) Make a vectors of the anonymous data and clear data
4) Generate a "ragged array" of the data in this form (i.e. dump out the records which are of variable length)
5) Bonus) Tell us which users jobs fail and how often as an absolute number, and as a fraction of the whole dataset.

# GPT Answer:
It uses a single secret key (HMAC) to anonymize users and IPv4s deterministically, builds vectors for both clear and anon data, emits a ragged array dump, and computes failure stats.

⚠️ For a real pipeline, load KEY_HEX from a secure store (KMS/HSM). For the assignment/MVP, a fixed value is fine so results are reproducible.

See `anon_demo.ipynb` for the implementation

#### Implementation notes
What each part delivers:
-Anon the user field + mapping

  anonymize_user_with_mapping() returns the anonymized Series and a dict {original_user -> token}.

- Anon the IP field (string or 32-bit int)

anonymize_ip_with_mapping() returns the anonymized IPv4 as a string and a dict
{original -> {"anon_ip": dotted_quad, "anon_ip_int": 32bit_int}}.
Format is preserved (valid IPv4), but prefix structure is not (MVP). If you later need prefix-preserving anonymization (e.g., Crypto-PAn), we can wire that in.

- Vectors of anonymous and clear data

make_vectors() produces two numpy.ndarrays (X_anon, X_clear).
Strings are stable-hashed to numbers; numerics pass through; datetimes → epoch ms; NaNs → -1. Adjust the encoder as needed for your models.

- Ragged array (variable length) dump

to_ragged_records() builds a list of lists [[("col", val), ...], ...].
dump_ragged_jsonl() writes one JSON line per record — naturally ragged.

- Bonus) Who’s failing and how often

failure_stats() returns a small table per user with:
fails, total, frac_of_user_rows, frac_of_all_rows.


#### Swap in your real data

Change USER_COL, IP_COL, FAILED_COL to the actual column names.
Replace demo = pd.DataFrame(...) with pd.read_parquet("your_file.parquet").
Keep KEY_HEX stable across runs (use file/KMS) to preserve deterministic mappings.


