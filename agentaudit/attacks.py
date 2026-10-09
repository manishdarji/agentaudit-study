"""Attacker A1: insider with write access to the log file but no signing key.

Every attack loads all rows, mutates them in memory, and writes them back, which
works for both the plain and the chained schema. With rehash=True the attacker
also recomputes hashes forward (the hash function is public). They still cannot
produce valid signatures, so that option tests whether the signature is what
actually protects the log. rewrite_with_key models attacker A2, who holds the key.
"""
import json
import sqlite3

from .events import GENESIS, canonical, entry_hash


def _load(path):
    conn = sqlite3.connect(path)
    cur = conn.execute("SELECT * FROM events ORDER BY seq")
    cols = [c[0] for c in cur.description]
    rows = [dict(zip(cols, r)) for r in cur.fetchall()]
    conn.close()
    return cols, rows


def _store(path, cols, rows):
    conn = sqlite3.connect(path)
    conn.execute("DELETE FROM events")
    marks = ",".join("?" * len(cols))
    conn.executemany(
        f"INSERT INTO events ({','.join(cols)}) VALUES ({marks})",
        [[r[c] for c in cols] for r in rows],
    )
    conn.commit()
    conn.close()


def _renumber(rows):
    for k, r in enumerate(rows):
        r["seq"] = k


def _rehash(rows, start=0, key=None):
    """Recompute prev_hash/entry_hash forward from `start`.

    Signatures are left stale unless a signing key is supplied (attacker A2 holds the key).
    """
    if not rows or "entry_hash" not in rows[0]:
        return
    prev = GENESIS if start == 0 else rows[start - 1]["entry_hash"]
    for r in rows[start:]:
        r["prev_hash"] = prev
        r["entry_hash"] = entry_hash(r["seq"], r["payload"], prev)
        if key is not None:
            r["sig"] = key.sign(bytes.fromhex(r["entry_hash"])).hex()
        prev = r["entry_hash"]


def rewrite_with_key(path, i, key):
    """Attacker A2: edit entry i, then re-hash and RE-SIGN everything after it with the stolen key."""
    cols, rows = _load(path)
    obj = json.loads(rows[i]["payload"])
    obj["result"] = "REWRITTEN"
    rows[i]["payload"] = canonical(obj)
    _rehash(rows, i, key=key)
    _store(path, cols, rows)


def edit_entry(path, i, rehash=False, key=None, value="TAMPERED"):
    """key=None: attacker A1 (cannot sign). key given: attacker A2 repairs hashes AND signatures."""
    cols, rows = _load(path)
    obj = json.loads(rows[i]["payload"])
    obj["result"] = value
    rows[i]["payload"] = canonical(obj)
    if rehash or key is not None:
        _rehash(rows, i, key=key)
    _store(path, cols, rows)


def delete_entry(path, i, rehash=False, key=None):
    cols, rows = _load(path)
    rows.pop(i)
    if rehash or key is not None:
        _renumber(rows)
        _rehash(rows, i, key=key)
    _store(path, cols, rows)


def delete_range(path, start, end=None, rehash=False, key=None):
    """Delete entries start..end-1 (end=None: everything from start on). end=None with start=0 empties the log."""
    cols, rows = _load(path)
    del rows[start:end]
    if rehash or key is not None:
        _renumber(rows)
        _rehash(rows, start, key=key)
    _store(path, cols, rows)


def reorder_entries(path, i, j, rehash=False, key=None):
    cols, rows = _load(path)
    rows[i], rows[j] = rows[j], rows[i]
    _renumber(rows)
    if rehash or key is not None:
        _rehash(rows, min(i, j), key=key)
    _store(path, cols, rows)


def insert_entry(path, i, forged_event, rehash=False, key=None):
    cols, rows = _load(path)
    forged = {c: "" for c in cols}
    forged["payload"] = canonical(forged_event)
    if "sig" in forged:
        forged["sig"] = "00" * 64  # replaced by a real signature only if the attacker holds the key
    rows.insert(i, forged)
    _renumber(rows)
    if rehash or key is not None:
        _rehash(rows, i, key=key)
    _store(path, cols, rows)


def truncate_tail(path, n):
    """Drop the last n entries, leaving a shorter but internally consistent log."""
    cols, rows = _load(path)
    _store(path, cols, rows[: len(rows) - n])
