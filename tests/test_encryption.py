import pytest
import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from crypto.encryption import CryptoManager

@pytest.fixture
def crypto():
    return CryptoManager()

def test_aes_encrypt_decrypt(crypto):
    key = crypto.generate_aes_key()
    msg = "Hello secure world!"
    ciphertext = crypto.aes_encrypt(key, msg)
    assert crypto.aes_decrypt(key, ciphertext) == msg

def test_aes_different_each_time(crypto):
    key = crypto.generate_aes_key()
    c1 = crypto.aes_encrypt(key, "same")
    c2 = crypto.aes_encrypt(key, "same")
    assert c1 != c2

def test_rsa_keypair(crypto):
    priv, pub = crypto.generate_rsa_keypair()
    aes_key = crypto.generate_aes_key()
    enc = crypto.rsa_encrypt_key(pub, aes_key)
    dec = crypto.rsa_decrypt_key(priv, enc)
    assert dec == aes_key

def test_hmac_valid(crypto):
    key = crypto.generate_aes_key()
    sig = crypto.sign_message(key, "test message")
    crypto.verify_message(key, "test message", sig)

def test_hmac_tampered(crypto):
    key = crypto.generate_aes_key()
    sig = crypto.sign_message(key, "original")
    with pytest.raises(ValueError):
        crypto.verify_message(key, "tampered", sig)

def test_replay_attack_blocked(crypto):
    seen = set()
    token = crypto.create_message_token("hi", crypto.generate_nonce())
    crypto.validate_token(token, seen)
    with pytest.raises(ValueError, match="replay"):
        crypto.validate_token(token, seen)

def test_expired_token_blocked(crypto):
    import time
    seen = set()
    token = {
        "message": "old",
        "nonce": "unique123",
        "timestamp": int(time.time()) - 60
    }
    with pytest.raises(ValueError, match="expired"):
        crypto.validate_token(token, seen, max_age=30)