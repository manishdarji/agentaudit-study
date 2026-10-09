import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

from agentaudit import attacks
from agentaudit.anchors import AnchoredLog, MissingDependency
from agentaudit.anchors.chain import ChainAnchorer, local_chain
from agentaudit.anchors.translog import Monitor, TransparencyAnchorer, TransparencyLog
from agentaudit.anchors.tsa import LocalTSA, TimestampAnchorer
from agentaudit.events import Anchor
from agentaudit.loggers import ChainedLog, generate_keypair
from agentaudit.verify import verify_chained

K = 10
N = 55  # anchors at lengths 10..50; entries 50..54 are the unanchored window


def event(i):
    return {"tool": "calc", "args": {"x": i}, "result": i * 2, "ts": 1000 + i}


def raw_pub(priv):
    return priv.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def skip_if_missing(factory):
    """Run factory(); if a required tool is not installed, skip the test and say how to fix it."""
    try:
        return factory()
    except MissingDependency as e:
        pytest.skip(str(e))


@pytest.fixture(params=["tsa", "translog", "chain"])
def backend(request, tmp_path):
    if request.param == "tsa":
        tsa = skip_if_missing(lambda: LocalTSA(str(tmp_path / "tsa")))
        return TimestampAnchorer(tsa, str(tmp_path / "escrow"))
    if request.param == "translog":
        key = Ed25519PrivateKey.generate()
        return TransparencyAnchorer(TransparencyLog(key), raw_pub(key))
    return skip_if_missing(lambda: ChainAnchorer(local_chain()))


@pytest.fixture
def keys():
    return generate_keypair()


def build(tmp_path, keys, backend):
    path = str(tmp_path / "log.db")
    log = AnchoredLog(ChainedLog(path, keys[0]), backend, K)
    for i in range(N):
        log.append(event(i))
    return path, log


def check(path, keys, backend):
    return verify_chained(path, keys[1], backend.published())


def test_backend_publishes_and_returns_anchors(tmp_path, keys, backend):
    path, log = build(tmp_path, keys, backend)
    assert len(backend.published()) == N // K
    assert check(path, keys, backend).ok
    assert all(r.latency_s >= 0 for r in log.receipts)


def test_truncation_beyond_window_is_detected(tmp_path, keys, backend):
    path, _ = build(tmp_path, keys, backend)
    attacks.truncate_tail(path, 7)  # 48 entries < last anchored length 50
    assert not check(path, keys, backend).ok


def test_truncation_inside_window_is_not_detected(tmp_path, keys, backend):
    path, _ = build(tmp_path, keys, backend)
    attacks.truncate_tail(path, 3)  # 52 entries, still covers anchor at 50
    assert check(path, keys, backend).ok


def test_attacker_with_key_cannot_rewrite_anchored_history(tmp_path, keys, backend):
    path, _ = build(tmp_path, keys, backend)
    attacks.rewrite_with_key(path, 20, keys[0])
    result = check(path, keys, backend)
    assert not result.ok and "before the anchor" in result.reason


def test_attacker_with_key_can_rewrite_unanchored_window(tmp_path, keys, backend):
    path, _ = build(tmp_path, keys, backend)
    attacks.rewrite_with_key(path, 52, keys[0])
    assert check(path, keys, backend).ok  # the compromise window


def test_rewrite_without_any_anchor_goes_unnoticed(tmp_path, keys):
    """M1 alone: an attacker holding the key can rewrite history undetected."""
    path = str(tmp_path / "log.db")
    log = ChainedLog(path, keys[0])
    for i in range(N):
        log.append(event(i))
    log.close()
    attacks.rewrite_with_key(path, 20, keys[0])
    assert verify_chained(path, keys[1]).ok


def test_chain_gas_is_recorded():
    anchorer = skip_if_missing(lambda: ChainAnchorer(local_chain()))
    r = anchorer.publish(Anchor(length=10, head_hash="ab" * 32))
    assert r.cost["gas"] > 21000
    assert anchorer.published() == [Anchor(length=10, head_hash="ab" * 32)]


def test_tsa_rejects_tampered_escrow(tmp_path):
    tsa = skip_if_missing(lambda: LocalTSA(str(tmp_path / "tsa")))
    a = TimestampAnchorer(tsa, str(tmp_path / "escrow"))
    a.publish(Anchor(length=10, head_hash="cd" * 32))
    assert len(a.published()) == 1
    # editing the stored anchor invalidates its timestamp token
    import json, glob
    f = glob.glob(str(tmp_path / "escrow" / "*.json"))[0]
    json.dump({"length": 10, "head": "ef" * 32}, open(f, "w"))
    assert a.published() == []


def test_translog_monitor_accepts_honest_growth_and_catches_split_view():
    key = Ed25519PrivateKey.generate()
    pub = raw_pub(key)
    log = TransparencyLog(key)
    monitor = Monitor(pub)
    for i in range(8):
        log.append(f"a{i}".encode())
    assert monitor.update(log)[0]
    for i in range(8, 20):
        log.append(f"a{i}".encode())
    assert monitor.update(log)[0]
    # a second view of the log that rewrote an early entry (same operator key signs both)
    forked = TransparencyLog(key)
    for i in range(20):
        forked.append(b"EVIL" if i == 3 else f"a{i}".encode())
    ok, reason = monitor.update(forked)
    assert not ok and "split view" in reason
