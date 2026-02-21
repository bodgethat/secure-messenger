from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os
import time
import hashlib
import hmac
import json

class CryptoManager:

    def generate_rsa_keypair(self):
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        return private_key, private_key.public_key()

    def serialize_public_key(self, public_key):
        return public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

    def load_public_key(self, pem_bytes):
        if isinstance(pem_bytes, str):
            pem_bytes = pem_bytes.encode()
        return serialization.load_pem_public_key(pem_bytes, backend=default_backend())

    def generate_aes_key(self):
        return os.urandom(32)

    def aes_encrypt(self, key, plaintext):
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(plaintext.encode()) + encryptor.finalize()
        return iv + ciphertext

    def aes_decrypt(self, key, ciphertext_with_iv):
        iv = ciphertext_with_iv[:16]
        ciphertext = ciphertext_with_iv[16:]
        cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        return (decryptor.update(ciphertext) + decryptor.finalize()).decode()

    def rsa_encrypt_key(self, public_key, aes_key):
        return public_key.encrypt(
            aes_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

    def rsa_decrypt_key(self, private_key, encrypted_key):
        return private_key.decrypt(
            encrypted_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

    def generate_nonce(self):
        return os.urandom(16).hex()

    def create_message_token(self, message, nonce):
        timestamp = int(time.time())
        return {"message": message, "nonce": nonce, "timestamp": timestamp}

    def validate_token(self, token, seen_nonces, max_age=30):
        now = int(time.time())
        if (now - token["timestamp"]) > max_age:
            raise ValueError("Message expired — possible replay attack!")
        if token["nonce"] in seen_nonces:
            raise ValueError("Duplicate nonce — replay attack detected!")
        seen_nonces.add(token["nonce"])
        return True

    def sign_message(self, key, message):
        return hmac.new(key, message.encode(), hashlib.sha256).hexdigest()

    def verify_message(self, key, message, signature):
        expected = hmac.new(key, message.encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected, signature):
            raise ValueError("Message integrity check failed — possible MITM!")