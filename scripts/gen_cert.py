# scripts/gen_cert.py
"""
Issue a certificate signed by the root CA.
Usage: python scripts/gen_cert.py server
Produces:
  certs/<name>_key.pem
  certs/<name>_cert.pem
"""
import os, sys, datetime
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization, hashes

OUT = "certs"
CA_KEY = os.path.join(OUT, "ca_key.pem")
CA_CERT = os.path.join(OUT, "ca_cert.pem")
os.makedirs(OUT, exist_ok=True)

def issue(name):
    if not os.path.exists(CA_KEY) or not os.path.exists(CA_CERT):
        print("CA not found. Run scripts/gen_ca.py first.")
        return

    with open(CA_KEY,"rb") as f:
        ca_key = serialization.load_pem_private_key(f.read(), password=None)
    with open(CA_CERT,"rb") as f:
        ca_cert = x509.load_pem_x509_certificate(f.read())

    # Generate key pair
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    key_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption()
    )

    with open(os.path.join(OUT, f"{name}_key.pem"), "wb") as f:
        f.write(key_pem)

    subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, name),
    ])

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.utcnow() - datetime.timedelta(days=1))
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(name)]),
            critical=False
        )
        .sign(ca_key, hashes.SHA256())
    )

    with open(os.path.join(OUT, f"{name}_cert.pem"), "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

    print("Wrote:", f"certs/{name}_key.pem", f"certs/{name}_cert.pem")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python scripts/gen_cert.py <name>")
    else:
        issue(sys.argv[1])
