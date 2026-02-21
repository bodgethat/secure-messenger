# Secure Messenger

End-to-End Encrypted messaging application built in Python.

## Features
- RSA + AES Hybrid Encryption
- bcrypt Password Hashing
- HMAC Message Integrity
- Replay Attack Prevention
- DoS Rate Limiting

## Setup
pip install -r requirements.txt

## Run
# Terminal 1 - Start server
python server/server.py

# Terminal 2 - Start client
python client/gui.py

## Tests
pytest tests/ -v