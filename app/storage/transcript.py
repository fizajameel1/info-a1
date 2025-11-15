# app/storage/transcript.py
import hashlib, os

TRANS_DIR = "transcripts"
os.makedirs(TRANS_DIR, exist_ok=True)

def append_line(session_id: str, seq: int, ts: int, ct_b64: str, sig_b64: str, peer_fp: str):
    path = os.path.join(TRANS_DIR, f"transcript_{session_id}.log")
    line = f"{seq}|{ts}|{ct_b64}|{sig_b64}|{peer_fp}\n"
    with open(path, "a") as f:
        f.write(line)
    return path

def transcript_hash(session_id: str) -> str:
    path = os.path.join(TRANS_DIR, f"transcript_{session_id}.log")
    with open(path, "rb") as f:
        data = f.read()
    return hashlib.sha256(data).hexdigest()
