"""
alice.py  –  Sisi Pengirim
Jalankan di laptop Alice:
    python alice.py --bob-ip 127.0.0.1 --port 9999
"""

import socket
import json
import base64
import hashlib
import os
import argparse

from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

def load_private_key(path):
    with open(path, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)

def load_public_key(path):
    with open(path, "rb") as f:
        return serialization.load_pem_public_key(f.read())

def b64(data: bytes) -> str:
    return base64.b64encode(data).decode()

def get_plaintext() -> bytes:
    print("End-to-End Secure Message Delivery")
    msg = input("\nMasukkan pesan yang akan dikirim ke Bob:\n> ")
    return msg.encode("utf-8")

def generate_symmetric_key():
    key = os.urandom(32)   # 256-bit
    iv  = os.urandom(16)   # 128-bit IV untuk AES-CBC
    print(f"\nSymmetric key (AES-256) dibuat")
    print(f"Key (hex): {key.hex()[:16]}...")
    return key, iv

def encrypt_message(plaintext: bytes, key: bytes, iv: bytes) -> bytes:
    # Padding manual (PKCS7)
    pad_len = 16 - (len(plaintext) % 16)
    padded  = plaintext + bytes([pad_len] * pad_len)

    cipher    = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded) + encryptor.finalize()

    print(f"\nPlaintext dienkripsi dengan AES-256-CBC")
    print(f"Ciphertext (hex): {ciphertext.hex()[:32]}...")
    return ciphertext

def encrypt_symmetric_key(key: bytes, bob_public_key) -> bytes:
    enc_key = bob_public_key.encrypt(
        key,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    print(f"\nSymmetric key dienkripsi dengan RSA-OAEP")
    print(f"Encrypted key (hex): {enc_key.hex()[:32]}...")
    return enc_key

def compute_hash(plaintext: bytes) -> bytes:
    digest = hashlib.sha256(plaintext).digest()
    print(f"\nHash SHA-256 dari plaintext:")
    print(f"{digest.hex()}")
    return digest

def sign_message(plaintext: bytes, alice_private_key) -> bytes:
    signature = alice_private_key.sign(
        plaintext,
        asym_padding.PSS(
            mgf=asym_padding.MGF1(hashes.SHA256()),
            salt_length=asym_padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    print(f"\nDigital signature dibuat dengan RSA-PSS")
    print(f"Signature (hex): {signature.hex()[:32]}...")
    return signature

def send_payload(payload: dict, bob_ip: str, port: int):
    raw = json.dumps(payload).encode("utf-8")

    print(f"\nMengirim payload ke {bob_ip}:{port}...")
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((bob_ip, port))
        s.sendall(len(raw).to_bytes(4, "big") + raw)

    print(f"Payload berhasil dikirim! ({len(raw)} bytes)")

def main():
    parser = argparse.ArgumentParser(description="Alice – Secure Sender")
    parser.add_argument("--bob-ip", required=True, help="IP address Bob")
    parser.add_argument("--port",   type=int, default=9999)
    args = parser.parse_args()

    # Load keys
    alice_private = load_private_key("keys/alice_private.pem")
    bob_public    = load_public_key("keys/bob_public.pem")

    # Proses pengamanan pesan
    plaintext   = get_plaintext()
    aes_key, iv = generate_symmetric_key()
    ciphertext  = encrypt_message(plaintext, aes_key, iv)
    enc_key     = encrypt_symmetric_key(aes_key, bob_public)
    msg_hash    = compute_hash(plaintext)
    signature   = sign_message(plaintext, alice_private)

    # Susun payload
    payload = {
        "sender"        : "Alice",
        "receiver"      : "Bob",
        "ciphertext"    : b64(ciphertext),
        "iv"            : b64(iv),
        "encrypted_key" : b64(enc_key),
        "hash"          : b64(msg_hash),
        "signature"     : b64(signature),
    }

    print("Format Payload:")
    for k, v in payload.items():
        display = v if k in ("sender", "receiver") else v[:24] + "..."
        print(f"{k:15s}: {display}")

    send_payload(payload, args.bob_ip, args.port)
    print("Pesan berhasil dikirim")

if __name__ == "__main__":
    main()
