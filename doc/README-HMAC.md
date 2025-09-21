# Fermilab Key–Value Data Anonymization (MVP)

This project provides a **deterministic, compression-friendly anonymization pipeline** for selected columns in Parquet/CSV data. It is designed for **key–value telemetry** where some metadata contains sensitive information (emails, proxy subjects, group names), while large binary blobs (e.g., physics detector data) **do not** require anonymization.

The goal is to **pseudonymize identifiers** while preserving:
- **Utility** (joins, group-bys, domain analysis).
- **Compression efficiency** (deterministic tokens compress well with Parquet/Zstd).
- **Scalability** (can run in batch jobs handling terabytes per day).

---

## How it Works

1. **HMAC-SHA-256 tokenization**  
   - Sensitive values are replaced with **HMAC tokens** (Base32-encoded, truncated).  
   - Deterministic: same input + key → same token.  
   - Irreversible without the secret key.

2. **Email anonymization**  
   - Local part is tokenized, domain preserved (e.g., `alice@fnal.gov` → `a1b2c3@fnal.gov`).  
   - Preserves domain-level analytics.

3. **Optional formats**  
   - Nulls (`None`, `NaN`) pass through unchanged.  
   - For strict mode, set `email_preserve_domain=False` to fully tokenize emails.  
   - Extendable to **Format-Preserving Encryption (FPE)** or **AES-SIV** if format retention or integrity is needed.

---

## What is HMAC?

**HMAC (Hash-based Message Authentication Code)** is a cryptographic construction that combines a **secret key** with a **hash function** (SHA-256 here).  

Properties:
- **Deterministic per key**: same key + same input → same token.  
- **One-way**: infeasible to recover the original value without the key.  
- **Keyed**: tokens are useless without the secret key; rotating keys changes all outputs.  

In this MVP, HMAC is used as a **tokenizer (pseudonymizer)** — not for message authentication.

---

## Key Management

- **Development mode:** generate a 256-bit key once with `os.urandom(32)`, save it locally (e.g., `../data/secret_key.bin`), and reload for deterministic runs.
- **Production mode:** use a **Key Management Service (KMS)** (AWS KMS, Google Cloud KMS, Azure Key Vault, or HSM).  
  - The pipeline fetches a **data key** at runtime.  
  - Only encrypted key blobs are stored on disk; plaintext keys never leave secure memory.

Helper function:
```python
from utils_secrets import gen_secret_hex

# Dev: creates/loads ../data/secret_key.bin
key_hex = gen_secret_hex(mode="dev", data_dir="../data")

# AWS KMS: requires AWS_REGION + AWS_KMS_KEY_ID env vars
key_hex = gen_secret_hex(mode="aws", data_dir="../data")
