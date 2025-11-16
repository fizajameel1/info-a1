# app/crypto/pki.py

from cryptography import x509
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
import datetime
import os

CA_CERT_PATH = os.path.join("certs", "ca_cert.pem")
CA_KEY_PATH = os.path.join("certs", "ca_key.pem")


def load_cert(pem_bytes: bytes) -> x509.Certificate:
    """Load a PEM-encoded certificate and return an x509.Certificate object."""
    return x509.load_pem_x509_certificate(pem_bytes)


def load_ca_cert() -> x509.Certificate:
    """Load the CA certificate from certs/ca_cert.pem."""
    if not os.path.exists(CA_CERT_PATH):
        raise FileNotFoundError(f"CA certificate not found at {CA_CERT_PATH}")
    with open(CA_CERT_PATH, "rb") as f:
        return x509.load_pem_x509_certificate(f.read())


def load_ca_key():
    """Load the CA private key (if needed). Do not commit this key to git."""
    if not os.path.exists(CA_KEY_PATH):
        raise FileNotFoundError(f"CA private key not found at {CA_KEY_PATH}")
    with open(CA_KEY_PATH, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)


def verify_cert_signed_by_ca(cert: x509.Certificate) -> None:
    """
    Verify that `cert` was signed by our CA.

    Raises:
      - FileNotFoundError if CA cert missing
      - ValueError / InvalidSignature (propagated) if verification fails
      - ValueError if issuer does not match CA subject or cert expired/not yet valid
    """
    ca_cert = load_ca_cert()
    # Check issuer matches CA subject
    if cert.issuer != ca_cert.subject:
        raise ValueError("certificate issuer does not match CA subject")

    # Verify signature using CA public key. Must pass the signature algorithm.
    ca_pub = ca_cert.public_key()
    ca_pub.verify(
        cert.signature,
        cert.tbs_certificate_bytes,
        padding.PKCS1v15(),
        cert.signature_hash_algorithm,
    )

    # Check validity window
    now = datetime.datetime.utcnow()
    if now < cert.not_valid_before or now > cert.not_valid_after:
        raise ValueError("certificate is not valid at the current time")


def check_cn(cert: x509.Certificate, expected_cn: str) -> None:
    """Check the Common Name (CN) in cert subject matches expected_cn. Raises ValueError on mismatch."""
    try:
        cn_attr = cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0]
    except Exception:
        raise ValueError("certificate has no Common Name (CN)")
    cn = cn_attr.value
    if cn != expected_cn:
        raise ValueError(f"CN mismatch: expected '{expected_cn}', got '{cn}'")


def cert_fingerprint_hex(cert: x509.Certificate) -> str:
    """Return the SHA-256 fingerprint of the certificate as a hex string."""
    return cert.fingerprint(hashes.SHA256()).hex()


def cert_pubkey(cert: x509.Certificate):
    """Return the public key object from a certificate."""
    return cert.public_key()
