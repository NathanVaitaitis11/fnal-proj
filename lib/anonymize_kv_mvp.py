"""
Unified anonymization module for key–value telemetry.
Supports two modes:
  - HMAC mode: deterministic HMAC-SHA256 Base32 tokens
  - FPE mode : format-preserving (uses pyffx if available, else deterministic shim)

Usage:
    from anonymize_kv_unified import anonymize_df_unified

    df2 = anonymize_df_unified(
        df,
        columns=["AccountingGroup","x509UserProxyEmail","x509userproxy","x509userproxysubject"],
        key_hex=key_hex,
        mode="hmac",   # or "fpe"
        email_preserve_domain=True,
    )
"""

import re, hmac, base64, hashlib
import pandas as pd
from typing import Any, Iterable, Optional

# Optional dependency for true FPE
try:
    import pyffx  # pip install pyffx
    _HAS_PYFFX = True
except Exception:
    _HAS_PYFFX = False

# --------------------------------------------------
# Common helpers
EMAIL_RE = re.compile(r"^([^@]+)@([^@]+\.[^@]+)$")
DIGITS = "0123456789"
LOWER  = "abcdefghijklmnopqrstuvwxyz"
UPPER  = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"

def _to_bytes(x: Any) -> bytes:
    if x is None:
        return b""
    try:
        if pd.isna(x):
            return b""
    except Exception:
        pass
    if isinstance(x, bytes):
        return x
    return str(x).encode("utf-8", errors="ignore")

# --------------------------------------------------
# HMAC mode
def token_hmac(value: Any, key: bytes, length: int = 22, case: str = "lower") -> str:
    mac = hmac.new(key, _to_bytes(value), hashlib.sha256).digest()
    tok = base64.b32encode(mac).decode("ascii").rstrip("=")[:length]
    return tok.lower() if case == "lower" else tok

def anonymize_email_hmac(value: Any, key: bytes, length: int = 16, preserve_domain: bool = True) -> Optional[str]:
    if value is None:
        return value
    try:
        if pd.isna(value):
            return value
    except Exception:
        pass
    s = str(value)
    m = EMAIL_RE.match(s)
    if not m:
        return token_hmac(s, key, length=length)
    local, domain = m.group(1), m.group(2)
    local_tok = token_hmac(local, key, length=length)
    return f"{local_tok}@{domain}" if preserve_domain else token_hmac(s, key, length=length+len(domain))

# --------------------------------------------------
# FPE mode (shim + optional pyffx)
def _hmac_digest(key: bytes, msg: bytes) -> bytes:
    return hmac.new(key, msg, hashlib.sha256).digest()

def _shim_map_char(ch: str, key: bytes, pos: int, salt: bytes = b"") -> str:
    if ch.isdigit():
        alphabet = DIGITS
    elif ch.islower():
        alphabet = LOWER
    elif ch.isupper():
        alphabet = UPPER
    else:
        return ch
    cls = b"d" if alphabet == DIGITS else (b"l" if alphabet == LOWER else b"u")
    msg = cls + bytes([pos & 0xFF]) + ch.encode("ascii", "ignore") + salt
    digest = _hmac_digest(key, msg)
    idx = digest[0] % len(alphabet)
    return alphabet[idx]

def fpe_shim_string(value: Any, key: bytes, salt: bytes = b"") -> Any:
    if value is None:
        return value
    try:
        if pd.isna(value):
            return value
    except Exception:
        pass
    s = str(value)
    return "".join(_shim_map_char(ch, key, i, salt) for i, ch in enumerate(s))

def fpe_string(value: Any, key: bytes, tweak: bytes = b"") -> Any:
    if value is None:
        return value
    try:
        if pd.isna(value):
            return value
    except Exception:
        pass
    s = str(value)

    if _HAS_PYFFX:
        only_digits = all(c.isdigit() for c in s) and len(s) > 0
        only_lower  = all(c.islower() for c in s) and len(s) > 0
        only_upper  = all(c.isupper() for c in s) and len(s) > 0
        alnum       = all(c.isalnum() for c in s) and len(s) > 0
        try:
            if only_digits:
                cipher = pyffx.Integer(key, length=len(s))
                return str(cipher.encrypt(int(s))).zfill(len(s))
            else:
                if only_lower:
                    alphabet = LOWER
                elif only_upper:
                    alphabet = UPPER
                elif alnum:
                    alphabet = LOWER + UPPER + DIGITS
                else:
                    observed = sorted(set([c for c in s if not c.isspace()]))
                    if len(observed) < 2:
                        return fpe_shim_string(s, key, salt=tweak)
                    alphabet = "".join(observed)
                cipher = pyffx.String(key, alphabet=alphabet, length=len(s))
                return cipher.encrypt(s)
        except Exception:
            return fpe_shim_string(s, key, salt=tweak)
    else:
        return fpe_shim_string(s, key, salt=tweak)

def anonymize_email_fpe(value: Any, key: bytes, preserve_domain: bool = True) -> Any:
    if value is None:
        return value
    try:
        if pd.isna(value):
            return value
    except Exception:
        pass
    s = str(value)
    m = EMAIL_RE.match(s)
    if not m:
        return fpe_string(s, key, tweak=b"email")
    local, domain = m.group(1), m.group(2)
    if preserve_domain:
        local_enc = fpe_string(local, key, tweak=b"email-local")
        return f"{local_enc}@{domain}"
    else:
        parts = domain.split(".")
        enc_local = fpe_string(local, key, tweak=b"email-local")
        enc_labels = [fpe_string(lbl, key, tweak=b"email-domain") for lbl in parts]
        return enc_local + "@" + ".".join(enc_labels)

# --------------------------------------------------
# Unified API
def anonymize_df(
    df: pd.DataFrame,
    columns: Iterable[str],
    key_hex: str,
    mode: str = "hmac",  # "hmac" | "fpe"
    in_place: bool = False,
    email_preserve_domain: bool = True,
    hmac_token_len: int = 22,
    hmac_email_len: int = 16,
) -> tuple[pd.DataFrame, list[dict]]:
    """
    Unified anonymizer with mode flag.

    Returns:
      (anonymized_df, mapping_list)
      - anonymized_df : DataFrame with sensitive values replaced
      - mapping_list  : list of dicts per row; each dict holds {col: (original, anonymized)} pairs
    """
    key = bytes.fromhex(key_hex)
    work = df if in_place else df.copy(deep=True)

    mapping_list: list[dict] = []

    for i, row in work.iterrows():
        row_map = {}
        for col in columns:
            if col not in work.columns:
                continue
            original = row[col]

            if mode == "hmac":
                if "email" in col.lower():
                    anonymized = anonymize_email_hmac(
                        original, key,
                        length=hmac_email_len,
                        preserve_domain=email_preserve_domain,
                    )
                else:
                    anonymized = token_hmac(original, key, length=hmac_token_len)
            elif mode == "fpe":
                if "email" in col.lower():
                    anonymized = anonymize_email_fpe(original, key, preserve_domain=email_preserve_domain)
                else:
                    tweak = str(col).encode("utf-8", errors="ignore")
                    anonymized = fpe_string(original, key, tweak=tweak)
            else:
                raise ValueError("mode must be 'hmac' or 'fpe'")

            # Update DataFrame
            work.at[i, col] = anonymized
            # Add to mapping dictionary
            row_map[col] = {"original": original, "anonymized": anonymized}

        mapping_list.append(row_map)

    return work, mapping_list
