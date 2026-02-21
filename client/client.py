import socket
import json
import threading
import queue
import sys
import os
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os as _os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from crypto.encryption import CryptoManager


class SecureClient:
    def __init__(self, host='127.0.0.1', port=9999):
        self.host = host
        self.port = port
        self.crypto = CryptoManager()
        self.username = None
        self.seen_nonces = set()
        self.message_callback = None
        self._send_lock = threading.Lock()
        self._response_queue = queue.Queue()

        # Generate fresh RSA keys every session
        self.private_key, self.public_key = self.crypto.generate_rsa_keypair()
        self.public_key_pem = self.crypto.serialize_public_key(self.public_key).decode()

        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.connect((self.host, self.port))
        threading.Thread(target=self._listen, daemon=True).start()

    def _send(self, data):
        with self._send_lock:
            message = json.dumps(data).encode()
            self.sock.sendall(len(message).to_bytes(4, 'big') + message)

    def _read_one(self):
        raw_len = self.sock.recv(4)
        if not raw_len:
            return None
        msg_len = int.from_bytes(raw_len, 'big')
        data = b""
        while len(data) < msg_len:
            chunk = self.sock.recv(min(4096, msg_len - len(data)))
            if not chunk:
                return None
            data += chunk
        return json.loads(data.decode())

    def _listen(self):
        while True:
            try:
                data = self._read_one()
                if data is None:
                    break
                if data.get("action") == "incoming_message":
                    if self.message_callback:
                        self.message_callback(data)
                else:
                    self._response_queue.put(data)
            except Exception as e:
                print(f"[LISTEN ERROR] {e}")
                break

    def _get_response(self, timeout=15):
        try:
            return self._response_queue.get(timeout=timeout)
        except queue.Empty:
            raise Exception("Server did not respond in time")

    def register(self, username, password):
        # Always send current session's public key on register
        self._send({
            "action": "register",
            "username": username,
            "password": password,
            "public_key": self.public_key_pem
        })
        return self._get_response()

    def login(self, username, password):
        # On login, update server with current session's public key
        self._send({
            "action": "login",
            "username": username,
            "password": password,
            "public_key": self.public_key_pem  # send fresh key
        })
        response = self._get_response()
        if response and response["status"] == "ok":
            self.username = username
        return response

    def send_message(self, target, message):
        self._send({"action": "get_key", "target": target})
        key_response = self._get_response()
        if not key_response or key_response["status"] != "ok":
            return {"status": "error", "msg": "User not found"}

        target_pub_key = self.crypto.load_public_key(
            key_response["public_key"].encode()
        )
        aes_key = self.crypto.generate_aes_key()
        encrypted_key = self.crypto.rsa_encrypt_key(target_pub_key, aes_key)

        nonce = self.crypto.generate_nonce()
        token = self.crypto.create_message_token(message, nonce)
        token_str = json.dumps(token)

        encrypted_msg = self.crypto.aes_encrypt(aes_key, token_str)
        signature = self.crypto.sign_message(aes_key, token_str)

        payload = {
            "encrypted_key": encrypted_key.hex(),
            "encrypted_msg": encrypted_msg.hex(),
            "signature": signature
        }
        self._send({
            "action": "send_message",
            "target": target,
            "payload": payload
        })
        return self._get_response()

    def decrypt_message(self, data):
        try:
            payload = data["payload"]
            encrypted_key = bytes.fromhex(payload["encrypted_key"])
            encrypted_msg = bytes.fromhex(payload["encrypted_msg"])
            signature = payload["signature"]
            aes_key = self.crypto.rsa_decrypt_key(self.private_key, encrypted_key)
            token_str = self.crypto.aes_decrypt(aes_key, encrypted_msg)
            self.crypto.verify_message(aes_key, token_str, signature)
            token = json.loads(token_str)
            self.crypto.validate_token(token, self.seen_nonces)
            return token["message"], data["from"]
        except Exception as e:
            raise ValueError(f"Decryption failed: {e}")