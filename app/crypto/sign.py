# app/crypto/sign.py
"""
RSA sign / verify helpers using cryptography.
Provides:
 - load_private_key(pem_bytes)
 - load_public_key_from_cert(cert)  # cert is cryptography.x509.Certificate
 - sign_bytes(priv_key, data: bytes) -> signature bytes
 - verify_bytes(pub_key, signature: bytes, data: bytes) -> bool
"""
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

def load_private_key(pem_bytes: bytes):
    """
    Load a PEM-encoded private key (no password).
    """
    return serialization.load_pem_private_key(pem_bytes, password=None)

def load_public_key_from_cert(cert):
    """
    Given a cryptography.x509.Certificate, return its public key object.
    """
    return cert.public_key()

def sign_bytes(priv_key, data: bytes) -> bytes:
    """
    Sign data (bytes) using PKCS1v15 + SHA256.
    """
    return priv_key.sign(
        data,
        padding.PKCS1v15(),
        hashes.SHA256()
    )

def verify_bytes(pub_key, signature: bytes, data: bytes) -> bool:
    """
    Verify signature (PKCS1v15 + SHA256). Returns True if valid, False otherwise.
    """
    try:
        pub_key.verify(signature, data, padding.PKCS1v15(), hashes.SHA256())
        return True
    except Exception:
        return False
