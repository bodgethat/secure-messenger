import sqlite3
import bcrypt

class Database:
    def __init__(self, db_path="users.db"):
        self.conn = sqlite3.connect(db_path, check_same_thread=False)
        self._create_tables()

    def _create_tables(self):
        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                username TEXT PRIMARY KEY,
                password_hash TEXT NOT NULL,
                public_key TEXT NOT NULL
            )
        """)
        self.conn.commit()

    def register_user(self, username, password, public_key_pem):
        password_hash = bcrypt.hashpw(
            password.encode(), bcrypt.gensalt()
        ).decode()
        try:
            self.conn.execute(
                "INSERT INTO users VALUES (?, ?, ?)",
                (username, password_hash, public_key_pem)
            )
            self.conn.commit()
            return True
        except sqlite3.IntegrityError:
            return False

    def authenticate_user(self, username, password):
        cursor = self.conn.execute(
            "SELECT password_hash FROM users WHERE username=?", (username,)
        )
        row = cursor.fetchone()
        if row and bcrypt.checkpw(password.encode(), row[0].encode()):
            return True
        return False

    def get_public_key(self, username):
        cursor = self.conn.execute(
            "SELECT public_key FROM users WHERE username=?", (username,)
        )
        row = cursor.fetchone()
        return row[0] if row else None

    def update_public_key(self, username, public_key_pem):
        self.conn.execute(
            "UPDATE users SET public_key=? WHERE username=?",
            (public_key_pem, username)
        )
        self.conn.commit()