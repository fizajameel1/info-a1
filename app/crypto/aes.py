# app/crypto/aes.py
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

BLOCK = AES.block_size  # 16

def aes_encrypt(key: bytes, plaintext: bytes) -> bytes:
    """
    AES-128 ECB + PKCS7 padding (ECB used for assignment simplicity).
    Key must be 16 bytes.
    """
    if len(key) != 16:
        raise ValueError("Key length must be 16 bytes")
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(pad(plaintext, BLOCK))

def aes_decrypt(key: bytes, ciphertext: bytes) -> bytes:
    if len(key) != 16:
        raise ValueError("Key length must be 16 bytes")
    cipher = AES.new(key, AES.MODE_ECB)
    return unpad(cipher.decrypt(ciphertext), BLOCK)
