# tests/manual/invalid_test.py
# Create an in-memory self-signed cert (NOT signed by our CA) and send it in the hello JSON.
# Server should reply with {"type":"bad_cert", "msg": "..."}.

import socket, json, datetime
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

HOST = "127.0.0.1"
PORT = 9000

# generate a short-lived self-signed cert (NOT signed by your CA)
def gen_self_signed_cert_pem(common_name="forged-client"):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)          # self-signed: issuer == subject
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.utcnow() - datetime.timedelta(days=1))
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=30))
        .sign(key, hashes.SHA256())
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode()
    key_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption()
    ).decode()
    return cert_pem, key_pem

def main():
    cert_pem, key_pem = gen_self_signed_cert_pem("forged-client")
    hello = {"type":"hello", "client_cert": cert_pem, "nonce": "invalid-test-1"}

    with socket.create_connection((HOST, PORT)) as s:
        s.sendall(json.dumps(hello).encode())
        resp = s.recv(200000)
        if not resp:
            print("No response")
            return
        try:
            jr = json.loads(resp.decode())
            print("Server response JSON:")
            print(json.dumps(jr, indent=2))
        except Exception:
            print("Raw response:", resp)

if __name__ == "__main__":
    main()
