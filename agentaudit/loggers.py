"""M0 (plain log) and M1 (signed hash chain). SQLite-backed so attackers can touch the file."""
import sqlite3

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .events import GENESIS, Anchor, canonical, entry_hash


def generate_keypair():
    """Return (private_key_object, raw_public_key_bytes)."""
    priv = Ed25519PrivateKey.generate()
    pub = priv.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    return priv, pub


class PlainLog:
    """M0: append rows, no integrity of any kind."""

    def __init__(self, path: str):
        self.conn = sqlite3.connect(path)
        self.conn.execute(
            "CREATE TABLE IF NOT EXISTS events ("
            "seq INTEGER PRIMARY KEY, payload TEXT NOT NULL)"
        )
        self.conn.commit()

    def append(self, event: dict) -> int:
        seq = self.conn.execute(
            "SELECT COALESCE(MAX(seq), -1) + 1 FROM events"
        ).fetchone()[0]
        self.conn.execute(
            "INSERT INTO events (seq, payload) VALUES (?, ?)", (seq, canonical(event))
        )
        self.conn.commit()
        return seq

    def close(self):
        self.conn.close()


class ChainedLog:
    """M1: each entry hashes its predecessor and is signed with Ed25519.

    Resumes an existing chain if the database already has entries.
    """

    def __init__(self, path: str, signing_key: Ed25519PrivateKey):
        self.conn = sqlite3.connect(path)
        self.key = signing_key
        self.conn.execute(
            "CREATE TABLE IF NOT EXISTS events ("
            "seq INTEGER PRIMARY KEY, payload TEXT NOT NULL, "
            "prev_hash TEXT NOT NULL, entry_hash TEXT NOT NULL, sig TEXT NOT NULL)"
        )
        self.conn.commit()
        row = self.conn.execute(
            "SELECT seq, entry_hash FROM events ORDER BY seq DESC LIMIT 1"
        ).fetchone()
        self._next_seq, self._head = (row[0] + 1, row[1]) if row else (0, GENESIS)

    def append(self, event: dict) -> int:
        payload = canonical(event)
        seq, prev = self._next_seq, self._head
        h = entry_hash(seq, payload, prev)
        sig = self.key.sign(bytes.fromhex(h)).hex()
        self.conn.execute(
            "INSERT INTO events (seq, payload, prev_hash, entry_hash, sig) "
            "VALUES (?, ?, ?, ?, ?)",
            (seq, payload, prev, h, sig),
        )
        self.conn.commit()
        self._next_seq, self._head = seq + 1, h
        return seq

    def anchor(self) -> Anchor:
        """Current (length, head hash). Publishing this externally is what M2-M4 add."""
        return Anchor(length=self._next_seq, head_hash=self._head)

    def close(self):
        self.conn.close()
