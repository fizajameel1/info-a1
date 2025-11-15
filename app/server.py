

import socket, json, base64, os, secrets, threading, time
from app.common.utils import b64e, b64d, now_ms, sha256_hex
from app.crypto import pki, dh as dhmod, aes as aesmod, sign as signmod
from app.storage import db as dbmod, transcript as tmod
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from app.common.protocol import Hello, ServerHello, DHClient, DHServer, Register, Login, Msg, Receipt
from app.crypto.sign import load_private_key, load_public_key_from_cert, verify_bytes, sign_bytes
import traceback

HOST = "0.0.0.0"
PORT = 9000
SERVER_CERT = "certs/server_cert.pem"
SERVER_KEY = "certs/server_key.pem"

# Use a safe group (small for speed here; for real assignment use RFC 3526 prime or crypto libs)
# We'll use 2048-bit MODP prime from RFC3526 (as a literal) to be robust.
RFC3526_2048 = int(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
    "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381"
    "FFFFFFFFFFFFFFFF", 16
)
DEFAULT_G = 2
DEFAULT_P = RFC3526_2048

# load server private key for signing receipts/messages
def load_server_privkey():
    with open(SERVER_KEY, "rb") as f:
        return load_private_key(f.read())

SERVER_PRIV = None
if os.path.exists(SERVER_KEY):
    try:
        SERVER_PRIV = load_server_privkey()
    except Exception:
        SERVER_PRIV = None

# helper to send JSON
def send_json(conn, obj):
    conn.sendall(json.dumps(obj).encode())

# helper to receive JSON (one recv)
def recv_json(conn, buf=200000):
    raw = conn.recv(buf)
    if not raw:
        return None
    return json.loads(raw.decode())

def do_dh_server(g, p, A):
    """Server generates b, computes B and Ks_int and return (b, B, Ks_int)"""
    b = secrets.randbelow(p-2) + 2
    B = pow(g, b, p)
    Ks_int = pow(A, b, p)
    return b, B, Ks_int

def handle_client(conn, addr):
    session_id = f"{addr[0]}_{addr[1]}_{int(time.time())}"
    try:
        j = recv_json(conn)
        if j is None:
            return
        if j.get("type") != "hello":
            send_json(conn, {"type":"error","msg":"expected hello"})
            return
        # verify client cert
        client_cert_pem = j.get("client_cert").encode()
        client_cert = pki.load_cert(client_cert_pem)
        try:
            pki.verify_cert_signed_by_ca(client_cert)
        except Exception as e:
            send_json(conn, {"type":"bad_cert","msg":str(e)})
            return
        # send server hello with server cert
        server_cert_pem = open(SERVER_CERT,"r").read() if os.path.exists(SERVER_CERT) else ""
        send_json(conn, {"type":"server_hello","server_cert": server_cert_pem, "nonce": j.get("nonce","")})
        # Now wait for DH client params (for register/login)
        j2 = recv_json(conn)
        if j2 is None:
            return
        if j2.get("type") != "dh_client":
            send_json(conn, {"type":"error","msg":"expected dh_client"})
            return
        g = int(j2["g"])
        p = int(j2["p"])
        A = int(j2["A"])
        b, B, Ks_int = do_dh_server(g,p,A)
        # send B
        send_json(conn, {"type":"dh_server","B":str(B)})
        # derive AES key
        K = dhmod.derive_key_from_Ks_int(Ks_int)  # 16 bytes
        # now expect encrypted command (register/login)
        enc_msg = recv_json(conn)
        if enc_msg is None:
            return
        if enc_msg.get("type") not in ("register","login"):
            send_json(conn, {"type":"error","msg":"expected register/login encrypted"})
            return
        # decode base64 ciphertext
        ct = base64.b64decode(enc_msg.get("ct"))
        try:
            plain = aesmod.aes_decrypt(K, ct)
        except Exception as e:
            send_json(conn, {"type":"error","msg":"aes_decrypt failed:"+str(e)})
            return
        payload = json.loads(plain.decode())
        typ = payload.get("type")
        if typ == "register":
            # payload: {"type":"register","email":..,"username":..,"pwd":..}
            email = payload["email"]
            username = payload["username"]
            pwd = payload["pwd"]
            # create salt and store
            salt = secrets.token_bytes(16)
            import hashlib
            pwd_hash = hashlib.sha256(salt + pwd.encode()).hexdigest()
            try:
                dbmod.new_user(email, username, salt, pwd_hash)
            except Exception as e:
                send_json(conn, {"type":"error","msg":"db insert failed: "+str(e)})
                return
            send_json(conn, {"type":"register_ok"})
            return
        elif typ == "login":
            email = payload["email"]
            pwd = payload["pwd"]
            rec = dbmod.find_user_by_email(email)
            if not rec:
                send_json(conn, {"type":"login_fail","msg":"user not found"})
                return
            salt = rec["salt"]
            import hashlib, hmac
            expected = rec["pwd_hash"]
            got = hashlib.sha256(salt + pwd.encode()).hexdigest()
            if not hmac.compare_digest(expected, got):
                send_json(conn, {"type":"login_fail","msg":"bad password"})
                return
            # login success: proceed to session DH for chat
            send_json(conn, {"type":"login_ok","username":rec["username"]})
            # start session DH: expect client session DH params
            j3 = recv_json(conn)
            if j3 is None or j3.get("type") != "dh_client_session":
                send_json(conn, {"type":"error","msg":"expected dh_client_session"})
                return
            A_sess = int(j3["A"])
            g_sess = int(j3.get("g", DEFAULT_G))
            p_sess = int(j3.get("p", DEFAULT_P))
            b_sess = secrets.randbelow(p_sess-2) + 2
            B_sess = pow(g_sess, b_sess, p_sess)
            Ks_sess = pow(A_sess, b_sess, p_sess)
            # send server session B
            send_json(conn, {"type":"dh_server_session","B":str(B_sess)})
            Ksess = dhmod.derive_key_from_Ks_int(Ks_sess)
            # chat loop: receive encrypted msgs, verify signature & append to transcript
            seq_expected = 1
            peer_cert = client_cert
            peer_pub = peer_cert.public_key()
            sess_transcript_path = None
            while True:
                m = recv_json(conn)
                if m is None:
                    break
                if m.get("type") == "msg":
                    # verify signature over seq|ts|ct (we'll verify using SHA256 of that)
                    seq = int(m["seqno"])
                    ts = int(m["ts"])
                    ct_b64 = m["ct"]
                    sig_b64 = m["sig"]
                    sig = base64.b64decode(sig_b64)
                    # meta to verify: seq||ts||ct_b64 bytes
                    meta = (str(seq) + "|" + str(ts) + "|" + ct_b64).encode()
                    meta_hash = bytes.fromhex(sha256_hex(meta))
                    ok = verify_bytes(peer_pub, sig, meta_hash)
                    if not ok:
                        send_json(conn, {"type":"msg_error","msg":"signature invalid"})
                        continue
                    # decrypt and display (server could print)
                    try:
                        ct = base64.b64decode(ct_b64)
                        pt = aesmod.aes_decrypt(Ksess, ct)
                    except Exception as e:
                        send_json(conn, {"type":"msg_error","msg":"decrypt failed"})
                        continue
                    # append to transcript
                    peer_fp = peer_cert.fingerprint(hashes.SHA256()).hex()
                    sess_transcript_path = tmod.append_line(session_id, seq, ts, ct_b64, sig_b64, peer_fp)
                    print(f"[{session_id}] MSG from {rec['username']}: {pt.decode(errors='ignore')}")
                    seq_expected = max(seq_expected, seq+1)
                    # ack
                    send_json(conn, {"type":"msg_ok","seq":seq})
                elif m.get("type") == "session_end":
                    # compute transcript hash and sign
                    tr_hash = tmod.transcript_hash(session_id)
                    # sign with server priv
                    sig = None
                    if SERVER_PRIV:
                        sig = base64.b64encode(sign_bytes(SERVER_PRIV, tr_hash.encode())).decode()
                    receipt = {"type":"receipt","peer":rec["username"], "first_seq":1, "last_seq": seq_expected-1, "transcript_sha256": tr_hash, "sig": sig}
                    # save receipt file
                    rpath = os.path.join("transcripts", f"receipt_{session_id}.json")
                    with open(rpath, "w") as f:
                        json.dump(receipt, f)
                    send_json(conn, {"type":"session_receipt","path": rpath, "receipt": receipt})
                    break
                else:
                    send_json(conn, {"type":"error","msg":"unknown message"})
            return
        else:
            send_json(conn, {"type":"error","msg":"unknown inner payload"})
            return
    except Exception as e:
        traceback.print_exc()
        try:
            send_json(conn, {"type":"server_error","msg": str(e)})
        except:
            pass
    finally:
        try:
            conn.close()
        except:
            pass

def main():
    os.makedirs("transcripts", exist_ok=True)
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((HOST, PORT))
        s.listen(6)
        print("Server listening on", PORT)
        while True:
            conn, addr = s.accept()
            print("Connection from", addr)
            # handle each client in a new thread
            threading.Thread(target=handle_client, args=(conn, addr), daemon=True).start()

if __name__=="__main__":
    main()
