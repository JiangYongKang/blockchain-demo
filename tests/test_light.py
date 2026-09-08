"""Light-client verification tests — the core security requirement.

A light client trusts ONLY a set of validator public keys and receives a block
header, the >2/3 precommit votes, and a Merkle proof. These tests assert:

* a correct proof (account balance/nonce, contract storage slot) verifies;
* tampering with the balance, the nonce, the storage value, or any proof-path
  hash makes verification fail;
* no proof can be forged for an account or storage value that the state root
  does not commit;
* finality requires >2/3 of stake signing valid precommits over the exact
  header hash — insufficient stake, wrong hash, or a forged signature all fail.
"""

import copy
import json

import pytest

from blockchain_demo.contract import contract_address, word_hex
from blockchain_demo.crypto import AccountKey, KeyPair
from blockchain_demo import light
from blockchain_demo.state import ChainState
from blockchain_demo.types import (
    PRECOMMIT,
    block_hash,
    make_block,
    make_call_tx,
    make_deploy_tx,
    make_tx,
    make_vote,
    validate_tx,
)

from blockchain_demo.contract import OP_PUSH1, OP_SSTORE, OP_STOP
COUNTER_CODE = bytes([OP_PUSH1, 0x00, OP_SSTORE, OP_STOP]).hex()  # PUSH1 0 SSTORE STOP -> storage[0]=calldata


def _setup():
    vals = [KeyPair.generate() for _ in range(4)]
    validators = {k.public_hex: 100 for k in vals}
    accts = [AccountKey.generate() for _ in range(2)]
    genesis = {
        "chain_id": "test",
        "validators": validators,
        "balances": {a.address: 10_000 for a in accts},
    }
    return vals, validators, accts, genesis


def _finalize(vals, validators, st, txs, height=1, prev="0" * 64):
    """Build a block over `txs`, set its state root, and collect precommits."""
    candidate = make_block(height, 0, prev, 1.0, vals[0].public_hex, txs, [])
    post = st.dry_run_block(candidate)
    block = make_block(
        height, 0, prev, 1.0, vals[0].public_hex, txs, [],
        app_state_root=post.state_root(),
    )
    st.apply_block(block)
    h = block_hash(block)
    commits = [make_vote(vk, PRECOMMIT, height, 0, h) for vk in vals]
    return block, block["header"], commits, post


# ------------------------------------------------------------------ finality
def test_finality_accepts_supermajority_and_rejects_less():
    vals, validators, accts, genesis = _setup()
    st = ChainState(genesis)
    _, header, commits, _ = _finalize(vals, validators, st, [])
    assert light.verify_finality(header, commits, validators)
    # Only 2 of 4 (200/400 = 1/2, not > 2/3): not final.
    assert not light.verify_finality(header, commits[:2], validators)
    # 3 of 4 (300/400 > 2/3): final.
    assert light.verify_finality(header, commits[:3], validators)


def test_finality_rejects_votes_for_other_block():
    vals, validators, accts, genesis = _setup()
    st = ChainState(genesis)
    _, header, commits, _ = _finalize(vals, validators, st, [])
    # Votes over a different block hash must not finalize this header.
    other = [make_vote(vk, PRECOMMIT, header["height"], 0, "ff" * 32) for vk in vals]
    assert not light.verify_finality(header, other, validators)


def test_finality_rejects_forged_vote_signature():
    vals, validators, accts, genesis = _setup()
    st = ChainState(genesis)
    _, header, commits, _ = _finalize(vals, validators, st, [])
    forged = copy.deepcopy(commits)
    forged[0]["signature"] = "00" * 64  # corrupt one signature
    assert not light.verify_finality(header, forged, validators)


def test_finality_unknown_validator_carries_no_weight():
    vals, validators, accts, genesis = _setup()
    st = ChainState(genesis)
    _, header, _, _ = _finalize(vals, validators, st, [])
    # Three unknown keys voting must not reach quorum.
    unknown = [KeyPair.generate() for _ in range(3)]
    votes = [make_vote(k, PRECOMMIT, header["height"], 0, block_hash({"header": header, "txs": [], "evidence": []})) for k in unknown]
    assert not light.verify_finality(header, votes, validators)


# ------------------------------------------------------------ account proofs
def test_balance_proof_verifies_after_transfer():
    vals, validators, accts, genesis = _setup()
    st = ChainState(genesis)
    tx = make_tx(accts[0], accts[1].address, 250, 0)
    block, header, commits, _ = _finalize(vals, validators, st, [tx])
    proof = st.account_proof(accts[1].address)
    result = light.verify_account(header, commits, validators, accts[1].address, proof)
    assert result is not None and result["exists"]
    assert result["balance"] == 10_250
    # sender debited
    sproof = st.account_proof(accts[0].address)
    sres = light.verify_account(header, commits, validators, accts[0].address, sproof)
    assert sres["balance"] == 9_750 and sres["nonce"] == 1


def test_absence_proof_proves_account_does_not_exist():
    vals, validators, accts, genesis = _setup()
    st = ChainState(genesis)
    _, header, commits, _ = _finalize(vals, validators, st, [])
    stranger = AccountKey.generate().address
    proof = st.account_proof(stranger)
    result = light.verify_account(header, commits, validators, stranger, proof)
    assert result is not None and not result["exists"]


def test_tampered_balance_fails():
    vals, validators, accts, genesis = _setup()
    st = ChainState(genesis)
    tx = make_tx(accts[0], accts[1].address, 100, 0)
    _, header, commits, _ = _finalize(vals, validators, st, [tx])
    proof = st.account_proof(accts[1].address)
    leaf = json.loads(proof["value"])
    leaf["balance"] = 999_999  # the attack: claim a huge balance
    proof["value"] = json.dumps(leaf, sort_keys=True, separators=(",", ":"))
    assert light.verify_account(header, commits, validators, accts[1].address, proof) is None


def test_tampered_nonce_fails():
    vals, validators, accts, genesis = _setup()
    st = ChainState(genesis)
    _, header, commits, _ = _finalize(vals, validators, st, [])
    proof = st.account_proof(accts[0].address)
    leaf = json.loads(proof["value"])
    leaf["nonce"] = 5
    proof["value"] = json.dumps(leaf, sort_keys=True, separators=(",", ":"))
    assert light.verify_account(header, commits, validators, accts[0].address, proof) is None


def test_tampered_proof_path_fails():
    vals, validators, accts, genesis = _setup()
    st = ChainState(genesis)
    _, header, commits, _ = _finalize(vals, validators, st, [])
    proof = st.account_proof(accts[0].address)
    for i in range(0, len(proof["proof"]), 37):  # corrupt a few sibling hashes
        bad = copy.deepcopy(proof)
        bad["proof"][i][0] = "aa" * 32
        assert light.verify_account(header, commits, validators, accts[0].address, bad) is None


def test_proof_for_one_address_replayed_for_another_fails():
    vals, validators, accts, genesis = _setup()
    st = ChainState(genesis)
    _, header, commits, _ = _finalize(vals, validators, st, [])
    proof = st.account_proof(accts[0].address)
    # Present acct0's proof while claiming acct1's address.
    assert light.verify_account(header, commits, validators, accts[1].address, proof) is None


def test_cannot_forge_uncommitted_account():
    vals, validators, accts, genesis = _setup()
    st = ChainState(genesis)
    root = st.state_root()
    _, header, commits, _ = _finalize(vals, validators, st, [])
    # Hand-build a "proof" claiming a rich account exists, using a valid-looking
    # but fabricated leaf and an all-empty sibling path (the real absence path).
    victim = AccountKey.generate().address
    from blockchain_demo.state import account_key
    key = account_key(victim)
    fake_leaf = json.dumps(
        {"balance": 1_000_000, "nonce": 0, "code": "", "storage_root": "0" * 64},
        sort_keys=True, separators=(",", ":"),
    )
    empty_tree = st.account_proof(victim)  # real absence proof
    forged = copy.deepcopy(empty_tree)
    forged["value"] = fake_leaf  # swap the empty leaf for a rich one
    assert light.verify_account_proof(root, forged) is None


# ------------------------------------------------------------ storage proofs
def test_storage_slot_proof_verifies():
    vals, validators, accts, genesis = _setup()
    st = ChainState(genesis)
    st.apply_tx(make_deploy_tx(accts[0], COUNTER_CODE, 0))
    addr = contract_address(accts[0].address, 0)
    st.apply_tx(make_call_tx(accts[0], addr, 1, calldata=123))
    block, header, commits, _ = _finalize(vals, validators, st, [], height=2, prev="1" * 64)
    proof = st.storage_proof(addr, word_hex(0))
    result = light.verify_storage(header, commits, validators, addr, 0, proof)
    assert result is not None and result["exists"]
    assert int(result["value"], 16) == 123


def test_tampered_storage_value_fails():
    vals, validators, accts, genesis = _setup()
    st = ChainState(genesis)
    st.apply_tx(make_deploy_tx(accts[0], COUNTER_CODE, 0))
    addr = contract_address(accts[0].address, 0)
    st.apply_tx(make_call_tx(accts[0], addr, 1, calldata=5))
    _, header, commits, _ = _finalize(vals, validators, st, [], height=2, prev="1" * 64)
    proof = st.storage_proof(addr, word_hex(0))
    proof["value"] = word_hex(999_999)  # claim a different stored value
    assert light.verify_storage(header, commits, validators, addr, 0, proof) is None


def test_tampered_storage_root_in_account_leaf_fails():
    vals, validators, accts, genesis = _setup()
    st = ChainState(genesis)
    st.apply_tx(make_deploy_tx(accts[0], COUNTER_CODE, 0))
    addr = contract_address(accts[0].address, 0)
    st.apply_tx(make_call_tx(accts[0], addr, 1, calldata=5))
    _, header, commits, _ = _finalize(vals, validators, st, [], height=2, prev="1" * 64)
    proof = st.storage_proof(addr, word_hex(0))
    # Lie about the storage_root committed in the contract's account leaf.
    leaf = json.loads(proof["account"]["value"])
    leaf["storage_root"] = "ff" * 32
    proof["account"]["value"] = json.dumps(leaf, sort_keys=True, separators=(",", ":"))
    assert light.verify_storage(header, commits, validators, addr, 0, proof) is None


def test_storage_absence_proof_for_unset_slot():
    vals, validators, accts, genesis = _setup()
    st = ChainState(genesis)
    st.apply_tx(make_deploy_tx(accts[0], COUNTER_CODE, 0))
    addr = contract_address(accts[0].address, 0)
    _, header, commits, _ = _finalize(vals, validators, st, [], height=2, prev="1" * 64)
    proof = st.storage_proof(addr, word_hex(7))  # slot 7 never written
    result = light.verify_storage(header, commits, validators, addr, 7, proof)
    assert result is not None and not result["exists"]


def test_cannot_forge_uncommitted_storage_value():
    vals, validators, accts, genesis = _setup()
    st = ChainState(genesis)
    st.apply_tx(make_deploy_tx(accts[0], COUNTER_CODE, 0))
    addr = contract_address(accts[0].address, 0)
    _, header, commits, _ = _finalize(vals, validators, st, [], height=2, prev="1" * 64)
    # A valid storage proof for an unset (empty) slot, then swap in a value.
    proof = st.storage_proof(addr, word_hex(3))
    proof["value"] = word_hex(42)
    assert light.verify_storage(header, commits, validators, addr, 3, proof) is None
