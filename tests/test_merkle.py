"""Sparse Merkle tree + list Merkle root tests.

Covers the properties a state commitment needs: identical data -> identical
root, any data change -> different root, valid inclusion/absence proofs
verify, and tampering with a value or a proof path hash always fails.
"""

import copy

from blockchain_demo.crypto import sha256_hex
from blockchain_demo.merkle import DEPTH, SparseMerkleTree, merkle_root


def _kv(n):
    return {sha256_hex(f"key-{i}".encode()): f"value-{i}" for i in range(n)}

def test_empty_tree_root_is_stable():
    assert SparseMerkleTree({}).root() == SparseMerkleTree().root()
    # The empty root is a fixed 32-byte hex hash.
    assert len(SparseMerkleTree({}).root()) == 64


def test_root_is_deterministic_and_order_independent():
    data = _kv(20)
    a = SparseMerkleTree(data)
    # Insert in a different order; the dict backing is order-insensitive.
    shuffled = dict(reversed(list(data.items())))
    b = SparseMerkleTree(shuffled)
    assert a.root() == b.root()


def test_update_changes_root_and_deletion_restores_it():
    data = _kv(5)
    tree = SparseMerkleTree(data)
    empty_root = SparseMerkleTree({}).root()
    before = tree.root()
    assert before != empty_root
    tree.update(sha256_hex(b"new"), "v")
    assert tree.root() != before
    tree.update(sha256_hex(b"new"), "")  # delete -> back to original
    assert tree.root() == before


def test_inclusion_proof_verifies_for_every_present_key():
    data = _kv(30)
    tree = SparseMerkleTree(data)
    root = tree.root()
    for key, value in data.items():
        proof = tree.prove(key)
        assert len(proof) == DEPTH
        assert SparseMerkleTree.verify_proof(root, key, value, proof)


def test_absence_proof_verifies_for_missing_key():
    data = _kv(10)
    tree = SparseMerkleTree(data)
    root = tree.root()
    missing = sha256_hex(b"definitely-not-present")
    proof = tree.prove(missing)
    # An absent key proves the empty value at its path.
    assert SparseMerkleTree.verify_proof(root, missing, "", proof)


def test_tampered_value_fails_verification():
    data = _kv(10)
    tree = SparseMerkleTree(data)
    root = tree.root()
    key, value = next(iter(data.items()))
    proof = tree.prove(key)
    assert not SparseMerkleTree.verify_proof(root, key, value + "x", proof)
    assert not SparseMerkleTree.verify_proof(root, key, "forged", proof)


def test_tampered_proof_path_fails_verification():
    data = _kv(10)
    tree = SparseMerkleTree(data)
    root = tree.root()
    key, value = next(iter(data.items()))
    proof = tree.prove(key)
    for i in range(len(proof)):
        bad = copy.deepcopy(proof)
        bad[i][0] = "ff" * 32  # corrupt one sibling hash
        assert not SparseMerkleTree.verify_proof(root, key, value, bad), f"step {i}"


def test_wrong_direction_fails_verification():
    data = _kv(10)
    tree = SparseMerkleTree(data)
    root = tree.root()
    key, value = next(iter(data.items()))
    proof = tree.prove(key)
    # Flip a direction bit; it also becomes inconsistent with the key.
    bad = copy.deepcopy(proof)
    bad[0][1] ^= 1
    assert not SparseMerkleTree.verify_proof(root, key, value, bad)


def test_proof_for_one_key_cannot_verify_another_key():
    data = _kv(10)
    tree = SparseMerkleTree(data)
    root = tree.root()
    keys = list(data)
    proof = tree.prove(keys[0])
    # Present the proof/value of keys[0] while claiming a different key.
    assert not SparseMerkleTree.verify_proof(root, keys[1], data[keys[0]], proof)


def test_malformed_proofs_rejected():
    data = _kv(3)
    tree = SparseMerkleTree(data)
    root = tree.root()
    key = next(iter(data))
    proof = tree.prove(key)
    assert not SparseMerkleTree.verify_proof(root, key, data[key], proof[:-1])  # too short
    bad = copy.deepcopy(proof)
    bad[0] = ["zz" * 32, 0]  # non-hex
    assert not SparseMerkleTree.verify_proof(root, key, data[key], bad)
    bad = copy.deepcopy(proof)
    bad[0] = [proof[0][0], 2]  # invalid direction
    assert not SparseMerkleTree.verify_proof(root, key, data[key], bad)


def test_list_merkle_root_properties():
    assert merkle_root([]) == sha256_hex(b"")
    h = lambda s: sha256_hex(s.encode())
    single = merkle_root([h("a")])
    assert single == h("a")  # a lone element is its own root
    two = merkle_root([h("a"), h("b")])
    assert two != single
    # Order matters; content matters; identical lists -> identical root.
    assert merkle_root([h("a"), h("b")]) != merkle_root([h("b"), h("a")])
    assert merkle_root([h("a"), h("b"), h("c")]) == merkle_root([h("a"), h("b"), h("c")])
    # Changing one element changes the root.
    assert merkle_root([h("a"), h("x")]) != two
