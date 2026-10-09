"""M3: an append-only Merkle transparency log with signed tree heads (RFC 6962 style).

The log is operated separately from the agent operator. A monitor that remembers earlier
signed tree heads and demands consistency proofs is what exposes a split view (fork).
"""
import time
from dataclasses import dataclass
from typing import Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from .. import merkle
from ..events import canonical
from . import Receipt, anchor_bytes, anchor_from_bytes


@dataclass(frozen=True)
class STH:
    size: int
    root: str  # hex
    sig: str  # hex


def _sth_message(size: int, root_hex: str) -> bytes:
    return canonical({"size": size, "root": root_hex}).encode("utf-8")


class TransparencyLog:
    def __init__(self, signing_key: Ed25519PrivateKey):
        self._key = signing_key
        self.entries = []
        self._leaves = []

    def append(self, data: bytes) -> int:
        self.entries.append(data)
        self._leaves.append(merkle.leaf_hash(data))
        return len(self.entries) - 1

    def sth(self, size: Optional[int] = None) -> STH:
        size = len(self._leaves) if size is None else size
        root_hex = merkle.root(self._leaves[:size]).hex()
        sig = self._key.sign(_sth_message(size, root_hex)).hex()
        return STH(size, root_hex, sig)

    def inclusion_proof(self, index: int, size: Optional[int] = None) -> list:
        size = len(self._leaves) if size is None else size
        return merkle.inclusion_proof(index, self._leaves[:size])

    def consistency_proof(self, old_size: int, new_size: Optional[int] = None) -> list:
        new_size = len(self._leaves) if new_size is None else new_size
        return merkle.consistency_proof(old_size, self._leaves[:new_size])


def verify_sth(sth: STH, public_key: bytes) -> bool:
    try:
        Ed25519PublicKey.from_public_bytes(public_key).verify(
            bytes.fromhex(sth.sig), _sth_message(sth.size, sth.root)
        )
        return True
    except (InvalidSignature, ValueError):
        return False


class Monitor:
    """Remembers the last verified tree head and checks every new one is a consistent extension."""

    def __init__(self, public_key: bytes):
        self.pub = public_key
        self.last: Optional[STH] = None

    def update(self, log: TransparencyLog):
        new = log.sth()
        if not verify_sth(new, self.pub):
            return False, "tree head signature invalid"
        if self.last is None or self.last.size == 0:
            self.last = new
            return True, "ok"
        if new.size < self.last.size:
            return False, "log shrank"
        proof = log.consistency_proof(self.last.size, new.size)
        ok = merkle.verify_consistency(
            self.last.size, new.size, bytes.fromhex(self.last.root), bytes.fromhex(new.root), proof
        )
        if not ok:
            return False, "new tree head is not consistent with the one seen before (split view)"
        self.last = new
        return True, "ok"


class TransparencyAnchorer:
    name = "M3-translog"

    def __init__(self, log: TransparencyLog, public_key: bytes):
        self.log, self.pub = log, public_key

    def publish(self, anchor) -> Receipt:
        t0 = time.perf_counter()
        data = anchor_bytes(anchor)
        idx = self.log.append(data)
        return Receipt(self.name, time.perf_counter() - t0, {"bytes": len(data)}, ref=str(idx))

    def published(self) -> list:
        """Anchors whose inclusion verifies against a correctly signed current tree head."""
        sth = self.log.sth()
        if not verify_sth(sth, self.pub):
            return []
        root = bytes.fromhex(sth.root)
        out = []
        for i, data in enumerate(self.log.entries):
            proof = self.log.inclusion_proof(i, sth.size)
            if merkle.verify_inclusion(merkle.leaf_hash(data), i, sth.size, proof, root):
                out.append(anchor_from_bytes(data))
        return out
