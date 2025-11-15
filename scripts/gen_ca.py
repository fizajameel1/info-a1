# scripts/gen_ca.py
"""
Create a Root CA (RSA key + self-signed X.509). Writes:
  certs/ca_key.pem   (private)  -- DO NOT COMMIT
  certs/ca_cert.pem  (public)
"""
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography import x509
from cryptography.x509.oid import NameOID
import datetime, os

OUT_DIR = "certs"
os.makedirs(OUT_DIR, exist_ok=True)

def main():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    key_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    with open(os.path.join(OUT_DIR, "ca_key.pem"), "wb") as f:
        f.write(key_pem)

    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, u"MyRootCA"),
    ])
    cert = x509.CertificateBuilder()\
        .subject_name(subject)\
        .issuer_name(issuer)\
        .public_key(key.public_key())\
        .serial_number(x509.random_serial_number())\
        .not_valid_before(datetime.datetime.utcnow() - datetime.timedelta(days=1))\
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=3650))\
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)\
        .sign(key, hashes.SHA256())

    with open(os.path.join(OUT_DIR, "ca_cert.pem"), "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

    print("Wrote certs/ca_key.pem and certs/ca_cert.pem. Do NOT commit ca_key.pem to git.")

if __name__=="__main__":
    main()
