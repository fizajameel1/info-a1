# app/client.py

import socket, json, base64, os, argparse, secrets, time
from app.common.utils import b64e, b64d, now_ms, sha256_hex
from app.crypto import pki, dh as dhmod, aes as aesmod, sign as signmod
from cryptography import x509
from cryptography.hazmat.primitives import serialization, hashes
from app.crypto.sign import load_private_key, sign_bytes, verify_bytes
from app.common.protocol import Hello
from app.storage import db as dbmod
import traceback, hashlib, hmac

SERVER_HOST = "127.0.0.1"
SERVER_PORT = 9000
CLIENT_CERT = "certs/client_cert.pem"
CLIENT_KEY = "certs/client_key.pem"
DEFAULT_G = 2
DEFAULT_P = dhmod.__dict__.get("DEFAULT_P", None)

def send_json(s, obj):
    s.sendall(json.dumps(obj).encode())

def recv_json(s, buf=200000):
    raw = s.recv(buf)
    if not raw:
        return None
    return json.loads(raw.decode())

def load_client_keys():
    if not os.path.exists(CLIENT_KEY) or not os.path.exists(CLIENT_CERT):
        raise FileNotFoundError("Missing client cert/key. Run scripts/gen_ca.py and scripts/gen_cert.py client")
    with open(CLIENT_CERT,"rb") as f:
        cert = x509.load_pem_x509_certificate(f.read())
    with open(CLIENT_KEY,"rb") as f:
        priv = load_private_key(f.read())
    return cert, priv

def do_register(email, username, pwd):
    cert, priv = load_client_keys()
    with socket.create_connection((SERVER_HOST, SERVER_PORT)) as s:
        hello = {"type":"hello","client_cert": open(CLIENT_CERT,"r").read(), "nonce":"n1"}
        send_json(s, hello)
        resp = recv_json(s)
        if resp is None or resp.get("type")!="server_hello":
            print("Server hello failed:", resp)
            return
        # verify server cert if present
        server_cert_pem = resp.get("server_cert")
        if server_cert_pem:
            try:
                sc = pki.load_cert(server_cert_pem.encode())
                pki.verify_cert_signed_by_ca(sc)
                print("Server cert OK")
            except Exception as e:
                print("Server cert verification failed:", e)
        # do ephemeral DH
        g = DEFAULT_G or 2
        p = DEFAULT_P or dhmod.__dict__.get("DEFAULT_P")
        a = secrets.randbelow(p-2) + 2
        A = pow(g, a, p)
        send_json(s, {"type":"dh_client","g":str(g),"p":str(p),"A":str(A)})
        srv = recv_json(s)
        if srv is None or srv.get("type")!="dh_server":
            print("DH server missing:", srv); return
        B = int(srv["B"])
        Ks_int = pow(B, a, p)
        K = dhmod.derive_key_from_Ks_int(Ks_int)
        # prepare register payload and encrypt with AES K
        payload = {"type":"register","email": email, "username": username, "pwd": pwd}
        pt = json.dumps(payload).encode()
        ct = aesmod.aes_encrypt(K, pt)
        send_json(s, {"type":"register","ct": base64.b64encode(ct).decode()})
        rr = recv_json(s)
        print("Server:", rr)

def do_login_then_chat(email, pwd, interactive=False):
    cert, priv = load_client_keys()
    with socket.create_connection((SERVER_HOST, SERVER_PORT)) as s:
        hello = {"type":"hello","client_cert": open(CLIENT_CERT,"r").read(), "nonce":"n1"}
        send_json(s, hello)
        resp = recv_json(s)
        if resp is None or resp.get("type")!="server_hello":
            print("Server hello failed:", resp)
            return
        # server cert validate
        server_cert_pem = resp.get("server_cert")
        if server_cert_pem:
            try:
                sc = pki.load_cert(server_cert_pem.encode())
                pki.verify_cert_signed_by_ca(sc)
                print("Server cert OK")
            except Exception as e:
                print("Server cert verification failed:", e)
        # ephemeral DH
        g = DEFAULT_G or 2
        p = DEFAULT_P or dhmod.__dict__.get("DEFAULT_P")
        a = secrets.randbelow(p-2) + 2
        A = pow(g, a, p)
        send_json(s, {"type":"dh_client","g":str(g),"p":str(p),"A":str(A)})
        srv = recv_json(s)
        if srv is None or srv.get("type")!="dh_server":
            print("DH server missing:", srv); return
        B = int(srv["B"])
        Ks_int = pow(B, a, p)
        K = dhmod.derive_key_from_Ks_int(Ks_int)
        # send login encrypted
        payload = {"type":"login","email": email, "pwd": pwd}
        pt = json.dumps(payload).encode()
        ct = aesmod.aes_encrypt(K, pt)
        send_json(s, {"type":"login","ct": base64.b64encode(ct).decode()})
        rr = recv_json(s)
        if rr is None:
            print("no response"); return
        if rr.get("type")!="login_ok":
            print("Login failed:", rr); return
        print("Login OK. Username:", rr.get("username"))
        # begin session DH for chat
        a_s = secrets.randbelow(p-2) + 2
        A_s = pow(g, a_s, p)
        send_json(s, {"type":"dh_client_session","g":str(g),"p":str(p),"A":str(A_s)})
        srv2 = recv_json(s)
        if srv2 is None or srv2.get("type")!="dh_server_session":
            print("session DH failed:", srv2); return
        B_s = int(srv2["B"])
        Ks_s = pow(B_s, a_s, p)
        Ksess = dhmod.derive_key_from_Ks_int(Ks_s)
        print("Session key established. Enter chat mode. Type /exit to end.")
        seq = 1
        # interactive chat loop
        while True:
            if interactive:
                msg = input("-> ")
            else:
                # non-interactive single message for script usage
                msg = "Hello from client automated message"
            if msg.strip() == "/exit":
                send_json(s, {"type":"session_end"})
                resp = recv_json(s)
                print("Session end response:", resp)
                break
            ct = aesmod.aes_encrypt(Ksess, msg.encode())
            ct_b64 = base64.b64encode(ct).decode()
            ts = now_ms()
            meta = (str(seq) + "|" + str(ts) + "|" + ct_b64).encode()
            meta_hash = hashlib.sha256(meta).digest()
            sig = sign_bytes(priv, meta_hash)
            sig_b64 = base64.b64encode(sig).decode()
            send_json(s, {"type":"msg","seqno": seq, "ts": ts, "ct": ct_b64, "sig": sig_b64})
            ack = recv_json(s)
            print("ACK:", ack)
            seq += 1
            if not interactive:
                # one message only in non-interactive mode
                # request session end to get receipt
                send_json(s, {"type":"session_end"})
                resp = recv_json(s)
                print("Session end response:", resp)
                break

def main():
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="cmd")
    p_reg = sub.add_parser("register")
    p_reg.add_argument("--email", required=True)
    p_reg.add_argument("--username", required=True)
    p_reg.add_argument("--pwd", required=True)
    p_log = sub.add_parser("login")
    p_log.add_argument("--email", required=True)
    p_log.add_argument("--pwd", required=True)
    p_chat = sub.add_parser("chat")
    p_chat.add_argument("--email", required=True)
    p_chat.add_argument("--pwd", required=True)
    p_chat.add_argument("--interactive", action="store_true")
    args = parser.parse_args()
    try:
        if args.cmd == "register":
            do_register(args.email, args.username, args.pwd)
        elif args.cmd == "login":
            do_login_then_chat(args.email, args.pwd, interactive=False)
        elif args.cmd == "chat":
            do_login_then_chat(args.email, args.pwd, interactive=args.interactive)
        else:
            parser.print_help()
    except Exception as e:
        traceback.print_exc()
        print("Error:", e)

if __name__=="__main__":
    main()
