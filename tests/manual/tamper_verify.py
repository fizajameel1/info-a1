# tests/tamper_verify.py
import os, hashlib, json, shutil, glob

TRANS_DIR = "transcripts"
t_files = glob.glob(os.path.join(TRANS_DIR,"transcript_*.log"))
r_files = glob.glob(os.path.join(TRANS_DIR,"receipt_*.json"))
if not t_files or not r_files:
    print("No transcripts or receipts found.")
    raise SystemExit(1)

tpath = t_files[0]
rpath = r_files[0]
print("Using:", tpath, rpath)

with open(tpath,"rb") as f:
    orig = f.read()
orig_hash = hashlib.sha256(orig).hexdigest()
print("Original hash:", orig_hash)

with open(rpath,"r") as f:
    receipt = json.load(f)
print("Receipt hash:", receipt.get("transcript_sha256"))

# Copy and tamper one byte in the copy
tampered = tpath + ".tampered"
shutil.copy(tpath, tampered)
with open(tampered,"r+b") as f:
    f.seek(0)
    b = f.read(1)
    if b:
        f.seek(0)
        f.write(bytes([b[0] ^ 0x01]))
    else:
        print("Transcript empty")
# compute tampered hash
with open(tampered,"rb") as f:
    tam_h = hashlib.sha256(f.read()).hexdigest()
print("Tampered hash:", tam_h)
print("Matches receipt?", tam_h == receipt.get("transcript_sha256"))
