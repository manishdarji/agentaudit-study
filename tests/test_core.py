import pytest

from agentaudit import attacks
from agentaudit.loggers import ChainedLog, PlainLog, generate_keypair
from agentaudit.verify import verify_chained, verify_plain

N = 50


def event(i):
    return {"tool": "calc", "args": {"x": i}, "result": i * 2, "ts": 1000 + i}


@pytest.fixture
def keys():
    return generate_keypair()


def build_plain(tmp_path):
    p = str(tmp_path / "plain.db")
    log = PlainLog(p)
    for i in range(N):
        log.append(event(i))
    log.close()
    return p


def build_chained(tmp_path, keys):
    p = str(tmp_path / "chained.db")
    log = ChainedLog(p, keys[0])
    for i in range(N):
        log.append(event(i))
    anchor = log.anchor()
    log.close()
    return p, anchor


# Each case: name, function applying the attack (rehash flag passed where relevant)
def attack_cases():
    forged = {"tool": "send_email", "args": {"to": "x"}, "result": "sent", "ts": 1}
    return [
        ("edit_naive", lambda p: attacks.edit_entry(p, 20)),
        ("edit_rehash", lambda p: attacks.edit_entry(p, 20, rehash=True)),
        ("edit_last_rehash", lambda p: attacks.edit_entry(p, N - 1, rehash=True)),
        ("delete_naive", lambda p: attacks.delete_entry(p, 20)),
        ("delete_rehash", lambda p: attacks.delete_entry(p, 20, rehash=True)),
        ("reorder_naive", lambda p: attacks.reorder_entries(p, 10, 30)),
        ("reorder_rehash", lambda p: attacks.reorder_entries(p, 10, 30, rehash=True)),
        ("insert_naive", lambda p: attacks.insert_entry(p, 20, forged)),
        ("insert_rehash", lambda p: attacks.insert_entry(p, 20, forged, rehash=True)),
    ]


def test_m1_clean_log_verifies(tmp_path, keys):
    p, anchor = build_chained(tmp_path, keys)
    assert verify_chained(p, keys[1], anchor).ok


def test_m1_resume_after_reopen(tmp_path, keys):
    p, _ = build_chained(tmp_path, keys)
    log = ChainedLog(p, keys[0])
    log.append(event(999))
    log.close()
    assert verify_chained(p, keys[1]).ok


def test_m1_wrong_key_fails(tmp_path, keys):
    p, _ = build_chained(tmp_path, keys)
    _, other_pub = generate_keypair()
    result = verify_chained(p, other_pub)
    assert not result.ok and result.reason == "invalid signature"


@pytest.mark.parametrize("name,attack", attack_cases(), ids=lambda x: x if isinstance(x, str) else "")
def test_m0_detects_nothing(tmp_path, name, attack):
    p = build_plain(tmp_path)
    attack(p)
    assert verify_plain(p).ok  # baseline: every attack succeeds silently


@pytest.mark.parametrize("name,attack", attack_cases(), ids=lambda x: x if isinstance(x, str) else "")
def test_m1_detects_in_place_tampering(tmp_path, keys, name, attack):
    p, _ = build_chained(tmp_path, keys)
    attack(p)
    result = verify_chained(p, keys[1])
    assert not result.ok, f"{name} was not detected"


def test_m1_rehash_attack_is_stopped_by_signature_not_hash(tmp_path, keys):
    p, _ = build_chained(tmp_path, keys)
    attacks.edit_entry(p, 20, rehash=True)
    result = verify_chained(p, keys[1])
    assert result.reason == "invalid signature" and result.first_bad_seq == 20


def test_m1_tail_truncation_undetected_without_anchor(tmp_path, keys):
    """Finding: a signed chain alone cannot see its own tail removed."""
    p, _ = build_chained(tmp_path, keys)
    attacks.truncate_tail(p, 5)
    assert verify_chained(p, keys[1]).ok


def test_m1_tail_truncation_detected_with_anchor(tmp_path, keys):
    p, anchor = build_chained(tmp_path, keys)
    attacks.truncate_tail(p, 5)
    result = verify_chained(p, keys[1], anchor)
    assert not result.ok and "shorter than anchored length" in result.reason


def test_anchor_still_valid_after_honest_growth(tmp_path, keys):
    p, anchor = build_chained(tmp_path, keys)
    log = ChainedLog(p, keys[0])
    for i in range(10):
        log.append(event(1000 + i))
    log.close()
    assert verify_chained(p, keys[1], anchor).ok
