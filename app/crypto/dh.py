# app/crypto/dh.py
import hashlib

def derive_key_from_Ks_int(Ks_int: int) -> bytes:
    """
    Convert shared integer Ks to 16-byte AES key:
      K = Trunc16(SHA256(big-endian(Ks)))
    """
    # big-endian byte representation
    blen = (Ks_int.bit_length() + 7) // 8
    ks_bytes = Ks_int.to_bytes(blen or 1, 'big')
    digest = hashlib.sha256(ks_bytes).digest()
    return digest[:16]
