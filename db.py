import sqlite3
from contextlib import contextmanager
from .config import settings

SCHEMA = """
CREATE TABLE IF NOT EXISTS licenses (
    key TEXT PRIMARY KEY,
    enabled INTEGER NOT NULL DEFAULT 1,
    expires_at INTEGER,
    created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS activations (
    activation_id TEXT PRIMARY KEY,
    license_key TEXT NOT NULL,
    public_key_b64 TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    expires_at INTEGER,
    FOREIGN KEY (license_key) REFERENCES licenses(key)
);
CREATE TABLE IF NOT EXISTS challenges (
    challenge_id TEXT PRIMARY KEY,
    activation_id TEXT NOT NULL,
    nonce_b64 TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    used INTEGER NOT NULL DEFAULT 0,
    FOREIGN KEY (activation_id) REFERENCES activations(activation_id)
);
CREATE INDEX IF NOT EXISTS idx_challenges_activation ON challenges(activation_id);
"""

def init_db():
    with sqlite3.connect(settings.database_path) as con:
        con.executescript(SCHEMA)
        con.commit()

@contextmanager
def db():
    con = sqlite3.connect(settings.database_path)
    con.row_factory = sqlite3.Row
    try:
        yield con
        con.commit()
    finally:
        con.close()
