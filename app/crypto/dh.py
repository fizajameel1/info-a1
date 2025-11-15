# app/crypto/dh.py
"""
DH helpers and key derivation.

Exports:
 - DEFAULT_P (2048-bit MODP prime from RFC3526)
 - DEFAULT_G (generator 2)
 - derive_key_from_Ks_int(Ks_int) -> 16-byte AES key (Trunc16(SHA256(Ks_bytes)))
 - gen_private(p) -> random private int
 - compute_public(g, priv, p) -> pow(g, priv, p)
"""
import hashlib
import secrets

# 2048-bit MODP Group (RFC 3526) as integer
DEFAULT_P = int(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74"
    "020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F1437"
    "4FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF05"
    "98DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9"
    "ED529077096966D670C354E4ABC9804F1746C08CA237327FFFFFFFFFFFFFFFF", 16
)
DEFAULT_G = 2

def derive_key_from_Ks_int(Ks_int: int) -> bytes:
    """
    Convert shared integer Ks to 16-byte AES key:
      K = Trunc16(SHA256(big-endian(Ks)))
    """
    blen = (Ks_int.bit_length() + 7) // 8
    ks_bytes = Ks_int.to_bytes(blen or 1, 'big')
    digest = hashlib.sha256(ks_bytes).digest()
    return digest[:16]

def gen_private(p: int = DEFAULT_P) -> int:
    """Generate a random private exponent in [2, p-2]."""
    return secrets.randbelow(p - 3) + 2

def compute_public(g: int, priv: int, p: int = DEFAULT_P) -> int:
    """Compute public value g^priv mod p."""
    return pow(g, priv, p)
