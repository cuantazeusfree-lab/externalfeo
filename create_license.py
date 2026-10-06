#!/usr/bin/env python3
import argparse
import secrets
import sqlite3
import string
import time
from pathlib import Path

def make_key():
    alphabet = string.ascii_uppercase + string.digits
    groups = ["".join(secrets.choice(alphabet) for _ in range(5)) for _ in range(4)]
    return "EXT-" + "-".join(groups)

parser = argparse.ArgumentParser()
parser.add_argument("--key")
parser.add_argument("--days", type=int, default=365)
parser.add_argument("--db", default="./external.db")
args = parser.parse_args()

key = args.key or make_key()
now = int(time.time())
expires = now + args.days * 86400 if args.days > 0 else None

Path(args.db).parent.mkdir(parents=True, exist_ok=True)
with sqlite3.connect(args.db) as con:
    con.execute("""CREATE TABLE IF NOT EXISTS licenses (
        key TEXT PRIMARY KEY,
        enabled INTEGER NOT NULL DEFAULT 1,
        expires_at INTEGER,
        created_at INTEGER NOT NULL
    )""")
    con.execute(
        "INSERT INTO licenses(key, enabled, expires_at, created_at) VALUES (?, 1, ?, ?)",
        (key, expires, now)
    )
    con.commit()

print(key)
