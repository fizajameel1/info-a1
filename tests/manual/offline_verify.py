import json, glob, hashlib
from cryptography.x509 import load_pem_x509_certificate
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes

def main():
    # find transcript and receipt
    t = glob.glob("transcripts/transcript_*.log")
    r = glob.glob("transcripts/receipt_*.json")

    if not t or not r:
        print("Error: transcript or receipt missing")
        return

    tpath, rpath = t[0], r[0]
    print(f"Using:\n  Transcript: {tpath}\n  Receipt:    {rpath}\n")

    # read and hash transcript
    with open(tpath, "rb") as f:
        data = f.read()

    computed_hash = hashlib.sha256(data).hexdigest()
    print("Computed Transcript SHA256:", computed_hash)

    # load receipt JSON
    receipt = json.load(open(rpath, "r"))
    receipt_hash = receipt.get("transcript_sha256")
    signature_b64 = receipt.get("sig")

    print("Receipt Transcript SHA256:", receipt_hash)
    print("Hashes match?:", computed_hash == receipt_hash)

    # now verify signature (non-repudiation)
    from base64 import b64decode
    sig = b64decode(signature_b64)

    # load client public key from certificate
    client_cert = load_pem_x509_certificate(open("certs/client_cert.pem", "rb").read())
    pubkey = client_cert.public_key()

    try:
        pubkey.verify(
            sig,
            computed_hash.encode(),
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        print("\nSignature valid?: True")
    except Exception as e:
        print("\nSignature valid?: False")
        print("Error:", e)

    print("\nOffline non-repudiation verification complete.")

if __name__ == "__main__":
    main()
