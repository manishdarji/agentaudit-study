"""External anchoring backends (M2 timestamp, M3 transparency log, M4 blockchain).

Every backend publishes the same Anchor (log length, head hash) and can later return
the anchors that verify under THAT medium's trust rules. The verifier is identical for all.
"""
from dataclasses import dataclass, field

from ..events import Anchor, canonical


class MissingDependency(RuntimeError):
    """A required external tool or package is not installed; the message says how to fix it."""


def anchor_bytes(a: Anchor) -> bytes:
    return canonical({"length": a.length, "head": a.head_hash}).encode("utf-8")


def anchor_from_bytes(data: bytes) -> Anchor:
    import json

    obj = json.loads(data.decode("utf-8"))
    return Anchor(length=obj["length"], head_hash=obj["head"])


@dataclass
class Receipt:
    backend: str
    latency_s: float
    cost: dict = field(default_factory=dict)  # e.g. {"gas": 71000} or {"bytes": 1400}
    ref: str = ""


class AnchoredLog:
    """Wraps a ChainedLog and publishes an anchor every k appended events."""

    def __init__(self, log, backend, k: int):
        self.log, self.backend, self.k = log, backend, k
        self.since_anchor = 0
        self.receipts = []

    def append(self, event: dict) -> int:
        seq = self.log.append(event)
        self.since_anchor += 1
        if self.since_anchor >= self.k:
            self.flush()
        return seq

    def flush(self) -> Receipt:
        r = self.backend.publish(self.log.anchor())
        self.receipts.append(r)
        self.since_anchor = 0
        return r
