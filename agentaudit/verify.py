"""Verifiers. Each returns a VerifyResult instead of raising, so experiments can tabulate outcomes."""
import sqlite3
from dataclasses import dataclass
from typing import Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .events import GENESIS, Anchor, entry_hash


@dataclass
class VerifyResult:
    ok: bool
    reason: str = "ok"
    first_bad_seq: Optional[int] = None


def verify_plain(path: str) -> VerifyResult:
    """M0 has nothing to check. Always passes; that is the point of the baseline."""
    return VerifyResult(True, "no integrity mechanism; nothing to check")


def verify_chained(
    path: str, public_key: bytes, anchor=None
) -> VerifyResult:
    """M1 verification, optionally against one anchor or a list of externally published anchors.

    Without an anchor, a chain cannot notice that its tail was cut off: the
    surviving prefix is still internally valid. The anchor closes that gap.
    """
    pub = Ed25519PublicKey.from_public_bytes(public_key)
    conn = sqlite3.connect(path)
    rows = conn.execute(
        "SELECT seq, payload, prev_hash, entry_hash, sig FROM events ORDER BY seq"
    ).fetchall()
    conn.close()

    prev = GENESIS
    for idx, (seq, payload, prev_hash, eh, sig) in enumerate(rows):
        if seq != idx:
            return VerifyResult(
                False, f"sequence gap or reorder: expected {idx}, found {seq}", idx
            )
        if prev_hash != prev:
            return VerifyResult(False, "broken link to previous entry", idx)
        if entry_hash(seq, payload, prev_hash) != eh:
            return VerifyResult(False, "entry hash does not match content", idx)
        try:
            pub.verify(bytes.fromhex(sig), bytes.fromhex(eh))
        except (InvalidSignature, ValueError):
            return VerifyResult(False, "invalid signature", idx)
        prev = eh

    if anchor is None:
        anchors = []
    elif isinstance(anchor, Anchor):
        anchors = [anchor]
    else:
        anchors = list(anchor)
    for a in sorted(anchors, key=lambda x: x.length):
        if len(rows) < a.length:
            return VerifyResult(
                False,
                f"log shorter than anchored length ({len(rows)} < {a.length})",
                len(rows),
            )
        if a.length > 0 and rows[a.length - 1][3] != a.head_hash:
            return VerifyResult(
                False, "history before the anchor differs from what was anchored",
                a.length - 1,
            )
    return VerifyResult(True)
