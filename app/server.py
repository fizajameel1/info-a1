# app/server.py
"""
Simple single-threaded server example for the assignment.
It expects JSON lines from the client. This is intentionally minimal
and demonstrates the control-plane: certificate exchange, DH, register/login.
"""
import socket, json
from app.common.utils import b64d, b64e
from app.crypto import pki, dh as dhmod, aes as aesmod
from app.storage import db as dbmod
from cryptography import x509

HOST = "0.0.0.0"
PORT = 9000

def handle_connection(conn):
    with conn:
        data = conn.recv(200000)
        if not data:
            return
        msg = json.loads(data.decode())
        # expecting Hello
        if msg.get("type") != "hello":
            conn.send(json.dumps({"type":"error","msg":"expected hello"}).encode())
            return
        client_cert_pem = msg.get("client_cert").encode()
        try:
            cert = pki.load_cert(client_cert_pem)
            pki.verify_cert_signed_by_ca(cert)
        except Exception as e:
            conn.send(json.dumps({"type":"bad_cert","msg":str(e)}).encode())
            return
        # send server hello with server cert file if present
        try:
            server_cert = open("certs/server_cert.pem","r").read()
        except:
            server_cert = ""
        resp = {"type":"server_hello","server_cert":server_cert, "nonce": msg.get("nonce","")}
        conn.send(json.dumps(resp).encode())
        # for a simple demo: respond OK
        # real code should now proceed with DH, registration or login
        # this file provides the control-plane hooks for the client to continue.
        return

def main():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((HOST, PORT))
        s.listen(5)
        print("Server listening on", PORT)
        while True:
            conn, addr = s.accept()
            print("Connection from", addr)
            handle_connection(conn)

if __name__ == "__main__":
    main()
