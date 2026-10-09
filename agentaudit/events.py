"""Canonical serialization and hashing shared by all logging mechanisms."""
import hashlib
import json
from dataclasses import dataclass

GENESIS = "00" * 32


def canonical(obj) -> str:
    """Deterministic JSON: sorted keys, no whitespace, UTF-8 safe."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def entry_hash(seq: int, payload: str, prev_hash: str) -> str:
    """Hash binds position, content and predecessor, so moving or editing any of them changes it."""
    blob = canonical({"seq": seq, "payload": payload, "prev": prev_hash}).encode("utf-8")
    return hashlib.sha256(blob).hexdigest()


@dataclass(frozen=True)
class Anchor:
    """A commitment to the log state at one moment, held somewhere the log owner cannot rewrite.

    M2 (timestamp), M3 (transparency log) and M4 (blockchain) differ in WHERE this
    lives and WHAT you must trust to believe it. The verifier only needs the values.
    """

    length: int
    head_hash: str
