# app/client.py
"""
Client skeleton: send hello with client_cert to server, receive server_hello.
"""
import socket, json
from app.crypto import pki
from cryptography import x509

HOST = "127.0.0.1"
PORT = 9000

def main():
    # read client cert
    try:
        client_cert = open("certs/client_cert.pem","r").read()
    except Exception:
        print("No certs/client_cert.pem found. Run scripts/gen_ca.py and scripts/gen_cert.py client")
        return
    hello = {"type":"hello", "client_cert": client_cert, "nonce":"n1"}
    with socket.create_connection((HOST, PORT)) as s:
        s.send(json.dumps(hello).encode())
        resp = s.recv(200000)
        print("Server response:", resp.decode())
        # validate server cert if provided
        try:
            jr = json.loads(resp.decode())
            server_cert_pem = jr.get("server_cert")
            if server_cert_pem:
                cert = pki.load_cert(server_cert_pem.encode())
                pki.verify_cert_signed_by_ca(cert)
                print("Server certificate validated OK")
        except Exception as e:
            print("Server cert validation failed:", e)

if __name__ == "__main__":
    main()
