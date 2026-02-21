import pytest
import sys
import os
import tempfile
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from server.database import Database

@pytest.fixture
def db():
    f = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
    return Database(f.name)

def test_register_success(db):
    assert db.register_user("alice", "pass123", "fake_key") is True

def test_register_duplicate(db):
    db.register_user("bob", "pass", "key")
    assert db.register_user("bob", "pass2", "key2") is False

def test_login_correct(db):
    db.register_user("carol", "mypassword", "key")
    assert db.authenticate_user("carol", "mypassword") is True

def test_login_wrong_password(db):
    db.register_user("dave", "correct", "key")
    assert db.authenticate_user("dave", "wrong") is False

def test_login_nonexistent_user(db):
    assert db.authenticate_user("nobody", "pass") is False

def test_get_public_key(db):
    db.register_user("eve", "pass", "EVE_PEM_KEY")
    assert db.get_public_key("eve") == "EVE_PEM_KEY"

def test_get_key_missing_user(db):
    assert db.get_public_key("ghost") is None