import pytest

from agentaudit import merkle


def leaves(n):
    return [merkle.leaf_hash(f"entry-{i}".encode()) for i in range(n)]


def test_inclusion_proofs_valid_for_all_sizes_and_indices():
    for n in range(1, 34):
        ls = leaves(n)
        r = merkle.root(ls)
        for i in range(n):
            assert merkle.verify_inclusion(ls[i], i, n, merkle.inclusion_proof(i, ls), r)


def test_inclusion_rejects_wrong_leaf_index_and_root():
    ls = leaves(11)
    r = merkle.root(ls)
    proof = merkle.inclusion_proof(4, ls)
    assert not merkle.verify_inclusion(merkle.leaf_hash(b"forged"), 4, 11, proof, r)
    assert not merkle.verify_inclusion(ls[4], 5, 11, proof, r)
    assert not merkle.verify_inclusion(ls[4], 4, 11, proof, merkle.root(leaves(10)))


def test_consistency_proofs_valid_for_all_size_pairs():
    for n in range(1, 34):
        ls = leaves(n)
        for m in range(1, n + 1):
            proof = merkle.consistency_proof(m, ls)
            assert merkle.verify_consistency(m, n, merkle.root(ls[:m]), merkle.root(ls), proof), (m, n)


def test_consistency_fails_for_divergent_history():
    honest = leaves(20)
    forked = honest[:5] + [merkle.leaf_hash(b"different")] + honest[6:]
    old_root = merkle.root(honest[:8])
    proof = merkle.consistency_proof(8, forked)
    assert not merkle.verify_consistency(8, 20, old_root, merkle.root(forked), proof)
