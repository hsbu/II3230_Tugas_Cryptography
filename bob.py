"""
bob.py  –  Sisi Penerima
Jalankan di laptop Bob SEBELUM Alice mengirim:
    python bob.py --port 9999
"""

import socket
import json
import base64
import hashlib
import argparse
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.exceptions import InvalidSignature    

def load_private_key(path):
    with open(path, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)

def load_public_key(path):
    with open(path, "rb") as f:
        return serialization.load_pem_public_key(f.read())

def b64d(s: str) -> bytes:
    return base64.b64decode(s)

def receive_payload(port: int) -> tuple[dict, str]:
    print(f"\nMenunggu koneksi di port {port}...")

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(("0.0.0.0", port))
        s.listen(1)
        conn, addr = s.accept()
        with conn:
            sender_ip = addr[0]
            print(f"Koneksi diterima dari {sender_ip}")

            raw_len = conn.recv(4)
            data_len = int.from_bytes(raw_len, "big")

            chunks = []
            received = 0
            while received < data_len:
                chunk = conn.recv(min(4096, data_len - received))
                if not chunk:
                    break
                chunks.append(chunk)
                received += len(chunk)

            raw = b"".join(chunks)
            payload = json.loads(raw.decode("utf-8"))

    print(f"Payload diterima ({len(raw)} bytes)")
    return payload, sender_ip

# Decrypt private key using RSA-OAEP
def decrypt_symmetric_key(enc_key_b64: str, bob_private_key) -> bytes:
    enc_key = b64d(enc_key_b64)
    aes_key = bob_private_key.decrypt(
        enc_key,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    print(f"\nSymmetric key berhasil didekripsi")
    print(f"Key (hex): {aes_key.hex()[:16]}...")
    return aes_key

# Decrypt ciphertext using AES-256-CBC
def decrypt_message(ciphertext_b64: str, iv_b64: str, aes_key: bytes) -> bytes:
    ciphertext = b64d(ciphertext_b64)
    iv         = b64d(iv_b64)

    cipher    = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    padded    = decryptor.update(ciphertext) + decryptor.finalize()

    # Hapus padding PKCS7
    pad_len  = padded[-1]
    plaintext = padded[:-pad_len]

    print(f"\nCiphertext berhasil didekripsi dengan AES-256-CBC")
    print(f"Plaintext: \"{plaintext.decode('utf-8')}\"")
    return plaintext

# Verify hash SHA-256
def verify_hash(plaintext: bytes, received_hash_b64: str) -> bool:
    computed = hashlib.sha256(plaintext).digest()
    received = b64d(received_hash_b64)

    match = (computed == received)
    status = "Valid" if match else "INvalid"
    print(f"\nHash SHA-256:")
    print(f"Diterima : {received.hex()}")
    print(f"Dihitung : {computed.hex()}")
    print(f"Status   : {status}")
    return match

# Verify digital signature
def verify_signature(plaintext: bytes, signature_b64: str, alice_public_key) -> bool:
    signature = b64d(signature_b64)
    try:
        alice_public_key.verify(
            signature,
            plaintext,
            asym_padding.PSS(
                mgf=asym_padding.MGF1(hashes.SHA256()),
                salt_length=asym_padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        valid = True
    except InvalidSignature:
        valid = False

    return valid

def print_conclusion(plaintext: bytes, hash_ok: bool, sig_ok: bool, sender_ip: str):
    print("\nDetails:")
    print(f"Pengirim IP : {sender_ip}")
    print(f"Pesan : \"{plaintext.decode('utf-8')}\"")
    print(f"Dekripsi : Berhasil")
    print(f"Integritas : {'Terjaga' if hash_ok else 'Hash tidak cocok'}")
    print(f"Autentikasi : {'Terverifikasi dari Alice' if sig_ok else 'Pesan tidak dapat terverifikasi'}")

    if hash_ok and sig_ok:
        print("\nPesan aman.")
    else:
        print("\n Ada masalah pada pesan ini!")

def main():
    parser = argparse.ArgumentParser(description="Bob – Secure Receiver")
    parser.add_argument("--port", type=int, default=9999)
    args = parser.parse_args()

    # Load keys
    bob_private   = load_private_key("keys/bob_private.pem")
    alice_public  = load_public_key("keys/alice_public.pem")

    # Proses penerimaan & verifikasi
    payload, sender_ip = receive_payload(args.port)

    print("\nMemproses payload...")
    aes_key   = decrypt_symmetric_key(payload["encrypted_key"], bob_private)
    plaintext = decrypt_message(payload["ciphertext"], payload["iv"], aes_key)
    hash_ok   = verify_hash(plaintext, payload["hash"])
    sig_ok    = verify_signature(plaintext, payload["signature"], alice_public)

    print_conclusion(plaintext, hash_ok, sig_ok, sender_ip)


if __name__ == "__main__":
    main()
