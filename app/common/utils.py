# app/common/utils.py
import base64
import time
import hashlib

def now_ms():
    """Return current time in milliseconds as int."""
    return int(time.time() * 1000)

def sha256_hex(data: bytes) -> str:
    """Return SHA256(data) as hex string."""
    return hashlib.sha256(data).hexdigest()

def b64e(b: bytes) -> str:
    """Base64 encode bytes -> str."""
    return base64.b64encode(b).decode()

def b64d(s: str) -> bytes:
    """Base64 decode str -> bytes."""
    return base64.b64decode(s)
