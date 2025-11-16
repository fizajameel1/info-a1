# scripts/test.py
"""
Hello test + server certificate validation
"""

import sys, os
# Add project root to Python path
sys.path.append(os.path.dirname(os.path.dirname(__file__)))

import socket, json
from app.crypto import pki

SERVER_HOST = "127.0.0.1"
SERVER_PORT = 9000

def run_test():
    client_cert = open("certs/client_cert.pem", "r").read()

    hello = {
        "type": "hello",
        "client_cert": client_cert,
        "nonce": "t1"
    }

    with socket.create_connection((SERVER_HOST, SERVER_PORT)) as s:
        s.sendall(json.dumps(hello).encode())
        raw = s.recv(200000)

    resp = json.loads(raw.decode())
    print("Server response JSON:")
    print(json.dumps(resp, indent=2))

    # Extract server certificate
    server_cert_pem = resp.get("server_cert")
    if not server_cert_pem:
        print("❌ No server cert in response!")
        return

    # Validate server certificate using our CA
    try:
        server_cert = pki.load_cert(server_cert_pem.encode())
        pki.verify_cert_signed_by_ca(server_cert)
        print("\n✅ Server certificate VALIDATED successfully against our CA")
    except Exception as e:
        print("\n❌ Server certificate validation FAILED:", e)

if __name__ == "__main__":
    run_test()
