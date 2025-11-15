# app/crypto/pki.py
from cryptography import x509
from cryptography.hazmat.primitives import serialization
import datetime

CA_CERT_PATH = "certs/ca_cert.pem"

def load_cert(pem_bytes: bytes):
    return x509.load_pem_x509_certificate(pem_bytes)

def verify_cert_signed_by_ca(cert: x509.Certificate) -> None:
    """
    Validates that cert was signed by our CA (simple approach: check issuer == CA.subject
    and verify signature using CA public key). Raises Exception on failure.
    """
    with open(CA_CERT_PATH, "rb") as f:
        ca = x509.load_pem_x509_certificate(f.read())
    # issuer match
    if cert.issuer != ca.subject:
        raise ValueError("issuer mismatch")
    # verify signature: use CA public key
    ca_pub = ca.public_key()
    # will raise if signature invalid
    ca_pub.verify(cert.signature, cert.tbs_certificate_bytes, cert.signature_hash_algorithm)
    # check validity window
    now = datetime.datetime.utcnow()
    if now < cert.not_valid_before or now > cert.not_valid_after:
        raise ValueError("certificate expired or not yet valid")

def check_cn(cert: x509.Certificate, expected_cn: str) -> None:
    cn = cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value
    if cn != expected_cn:
        raise ValueError(f"CN mismatch: expected {expected_cn} found {cn}")
