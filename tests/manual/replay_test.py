# tests/replay_test.py
import socket, json, base64, secrets
from app.crypto import dh as dhmod
from app.common.utils import b64e, b64d
from cryptography import x509

SERVER_HOST = "127.0.0.1"
SERVER_PORT = 9000
CLIENT_CERT = "certs/client_cert.pem"

def recv_json(s):
    raw = s.recv(200000)
    if not raw:
        return None
    return json.loads(raw.decode())

def send_json(s, obj):
    s.sendall(json.dumps(obj).encode())

def main():
    # Load client cert for hello
    client_cert_pem = open(CLIENT_CERT,"r").read()

    # Connect and send hello
    s = socket.create_connection((SERVER_HOST, SERVER_PORT))
    send_json(s, {"type":"hello","client_cert": client_cert_pem, "nonce":"replay1"})
    srv = recv_json(s)
    print("server_hello:", srv)

    # Do ephemeral DH (control-plane) for login step (we'll login)
    p = dhmod.DEFAULT_P
    g = dhmod.DEFAULT_G
    a = secrets.randbelow(p-2) + 2
    A = pow(g, a, p)
    send_json(s, {"type":"dh_client","g":str(g),"p":str(p),"A":str(A)})
    srv2 = recv_json(s)
    print("dh_server:", srv2)
    B = int(srv2["B"])
    Ks_int = pow(B, a, p)
    K = dhmod.derive_key_from_Ks_int(Ks_int)

    # For this replay test we assume the user is already registered.
    # Send encrypted login payload (we need login to reach session DH).
    import hashlib
    payload = {"type":"login","email":"test@example.com","pwd":"P@ssw0rd123"}
    import base64
    from app.crypto import aes as aesmod
    ct = aesmod.aes_encrypt(K, json.dumps(payload).encode())
    send_json(s, {"type":"login","ct": base64.b64encode(ct).decode()})
    rr = recv_json(s)
    print("login response:", rr)
    if rr.get("type") != "login_ok":
        print("login failed:", rr); s.close(); return

    # Now do session DH to establish a session key
    a_s = secrets.randbelow(p-2) + 2
    A_s = pow(g, a_s, p)
    send_json(s, {"type":"dh_client_session","g":str(g),"p":str(p),"A":str(A_s)})
    srv3 = recv_json(s)
    print("dh_server_session:", srv3)
    B_s = int(srv3["B"])
    Ks_s = pow(B_s, a_s, p)
    Ksess = dhmod.derive_key_from_Ks_int(Ks_s)

    # Load saved message JSON and send it exactly (this simulates replay)
    with open("tests/last_sent_msg.json","r") as f:
        msg_obj = json.load(f)
    print("Replaying message:", msg_obj)
    send_json(s, msg_obj)
    resp = recv_json(s)
    print("Server response to replay:", resp)
    s.close()

if __name__ == "__main__":
    main()
