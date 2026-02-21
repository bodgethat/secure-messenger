import socket
import threading
import json
import time
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from database import Database


class SecureServer:
    def __init__(self, host='127.0.0.1', port=9999):
        self.host = host
        self.port = port
        self.db = Database()
        self.clients = {}
        self.connection_attempts = {}

    def start(self):
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((self.host, self.port))
        server.listen(10)
        print(f"[SERVER] Running on {self.host}:{self.port}")
        while True:
            conn, addr = server.accept()
            print(f"[SERVER] New connection from {addr}")
            thread = threading.Thread(
                target=self.handle_client, args=(conn, addr))
            thread.daemon = True
            thread.start()

    def is_rate_limited(self, ip):
        now = time.time()
        attempts = self.connection_attempts.get(ip, [])
        attempts = [t for t in attempts if now - t < 60]
        if len(attempts) >= 10:
            return True
        attempts.append(now)
        self.connection_attempts[ip] = attempts
        return False

    def send(self, conn, data):
        try:
            message = json.dumps(data).encode()
            conn.sendall(len(message).to_bytes(4, 'big') + message)
        except Exception as e:
            print(f"[SEND ERROR] {e}")

    def receive(self, conn):
        try:
            raw_len = conn.recv(4)
            if not raw_len:
                return None
            msg_len = int.from_bytes(raw_len, 'big')
            data = b""
            while len(data) < msg_len:
                chunk = conn.recv(min(4096, msg_len - len(data)))
                if not chunk:
                    return None
                data += chunk
            return json.loads(data.decode())
        except Exception as e:
            print(f"[RECEIVE ERROR] {e}")
            return None

    def handle_client(self, conn, addr):
        ip = addr[0]
        if self.is_rate_limited(ip):
            self.send(conn, {"status": "error", "msg": "Rate limited"})
            conn.close()
            return

        username = None
        try:
            while True:
                data = self.receive(conn)
                if not data:
                    break

                action = data.get("action")
                print(f"[SERVER] Action: {action}")

                if action == "register":
                    success = self.db.register_user(
                        data["username"],
                        data["password"],
                        data["public_key"]
                    )
                    self.send(conn, {
                        "status": "ok" if success else "error",
                        "msg": "Registered successfully!" if success else "Username already taken!"
                    })

                elif action == "login":
                    if self.db.authenticate_user(data["username"], data["password"]):
                        username = data["username"]
                        self.clients[username] = conn
                        if "public_key" in data:
                            self.db.update_public_key(username, data["public_key"])
                        self.send(conn, {"status": "ok", "msg": "Login successful!"})
                        print(f"[SERVER] {username} logged in")
                    else:
                        self.send(conn, {"status": "error", "msg": "Invalid credentials!"})

                elif action == "get_key":
                    key = self.db.get_public_key(data["target"])
                    if key:
                        self.send(conn, {"status": "ok", "public_key": key})
                    else:
                        self.send(conn, {"status": "error", "msg": "User not found"})

                elif action == "send_message":
                    target = data["target"]
                    if target in self.clients:
                        self.send(self.clients[target], {
                            "action": "incoming_message",
                            "from": username,
                            "payload": data["payload"]
                        })
                        self.send(conn, {"status": "ok"})
                    else:
                        self.send(conn, {"status": "error", "msg": "User is not online"})

        except Exception as e:
            print(f"[SERVER ERROR] {e}")
        finally:
            if username and username in self.clients:
                del self.clients[username]
                print(f"[SERVER] {username} disconnected")
            conn.close()


if __name__ == "__main__":
    try:
        SecureServer().start()
    except Exception as e:
        print(f"[FATAL ERROR] {e}")
        input("Press Enter to exit...")