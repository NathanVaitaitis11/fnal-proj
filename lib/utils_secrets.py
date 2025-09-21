
import os
import pathlib
from typing import Optional

def _ensure_dir(p: str) -> None:
    pathlib.Path(p).mkdir(parents=True, exist_ok=True)

def _load_local_key(path: str) -> Optional[bytes]:
    try:
        with open(path, "rb") as f:
            key = f.read()
        if len(key) != 32:
            raise ValueError("Invalid key length in local file (expected 32 bytes).")
        return key
    except FileNotFoundError:
        return None

def _save_local_key(path: str, key: bytes) -> None:
    # Restrict permissions to owner only (best effort on POSIX)
    d = os.path.dirname(path)
    if d:
        os.makedirs(d, exist_ok=True)
    with open(path, "wb") as f:
        f.write(key)
    try:
        os.chmod(path, 0o600)
    except Exception:
        pass

def gen_secret_hex(mode: str = "dev", data_dir: str = "../data") -> str:
    """
    Generate or retrieve a deterministic 256-bit secret key for anonymization.

    Modes:
      - "dev": Create and store a local key at {data_dir}/secret_key.bin if missing; else load it.
      - "aws": Use AWS KMS to manage a data key; caches only the CiphertextBlob at {data_dir}/kms_data_key.bin.
               Requires AWS credentials and region; expects AWS_KMS_KEY_ID in env or uses one passed via env.

    Returns:
      Hex-encoded 32-byte key.
    """
    data_dir = os.path.abspath(data_dir)
    _ensure_dir(data_dir)

    if mode == "dev":
        key_path = os.path.join(data_dir, "secret_key.bin")
        key = _load_local_key(key_path)
        if key is None:
            key = os.urandom(32)
            _save_local_key(key_path, key)
        return key.hex()

    elif mode == "aws":
        # Lazy import to avoid hard dependency for dev
        try:
            import boto3  # type: ignore
        except Exception as e:
            raise RuntimeError("boto3 is required for mode='aws'. Install with `pip install boto3`.") from e

        region = os.environ.get("AWS_REGION") or os.environ.get("AWS_DEFAULT_REGION")
        if not region:
            raise RuntimeError("Set AWS_REGION (or AWS_DEFAULT_REGION) for mode='aws'.")
        kms_key_id = os.environ.get("AWS_KMS_KEY_ID")
        if not kms_key_id:
            raise RuntimeError("Set AWS_KMS_KEY_ID to your KMS CMK ARN or key ID for mode='aws'.")

        kms = boto3.client("kms", region_name=region)

        ct_path = os.path.join(data_dir, "kms_data_key.bin")
        if os.path.exists(ct_path):
            # Decrypt cached CiphertextBlob to get plaintext data key
            with open(ct_path, "rb") as f:
                ciphertext_blob = f.read()
            resp = kms.decrypt(CiphertextBlob=ciphertext_blob)
            key_bytes = resp["Plaintext"]
            if len(key_bytes) != 32:
                raise RuntimeError("Decrypted data key is not 32 bytes. Check KMS configuration.")
            return key_bytes.hex()
        else:
            # Generate a new data key; store only the CiphertextBlob to disk
            resp = kms.generate_data_key(KeyId=kms_key_id, KeySpec="AES_256")
            plaintext_key = resp["Plaintext"]
            ciphertext_blob = resp["CiphertextBlob"]
            if len(plaintext_key) != 32:
                raise RuntimeError("Generated data key is not 32 bytes. Check KMS configuration.")
            with open(ct_path, "wb") as f:
                f.write(ciphertext_blob)
            try:
                os.chmod(ct_path, 0o600)
            except Exception:
                pass
            return plaintext_key.hex()

    else:
        raise ValueError("mode must be 'dev' or 'aws'")
