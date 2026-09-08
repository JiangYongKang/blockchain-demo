from blockchain_demo.crypto import KeyPair
from blockchain_demo.types import (
    PRECOMMIT,
    PREVOTE,
    block_hash,
    evidence_culprit,
    evidence_key,
    make_block,
    make_evidence,
    make_proposal,
    make_tx,
    make_vote,
    validate_proposal,
    validate_tx,
    validate_vote,
)

GENESIS_HASH = "0" * 64


def _block(key, height=1, round_=0, ts=1.0):
    return make_block(height, round_, GENESIS_HASH, ts, key.public_hex, [], [])


def test_tx_validation():
    key = KeyPair.generate()
    tx = make_tx(key, "recipient", 10, 0)
    assert validate_tx(tx)
    tx["amount"] = 999  # tamper
    assert not validate_tx(tx)


def test_vote_validation():
    key = KeyPair.generate()
    vote = make_vote(key, PREVOTE, 1, 0, "aa" * 32)
    assert validate_vote(vote)
    vote["block_hash"] = "bb" * 32
    assert not validate_vote(vote)


def test_proposal_validation():
    key = KeyPair.generate()
    proposal = make_proposal(key, _block(key), 0)
    assert validate_proposal(proposal)
    proposal["block"]["timestamp"] = 2.0  # changes block hash
    assert not validate_proposal(proposal)


def test_double_vote_evidence():
    key = KeyPair.generate()
    v1 = make_vote(key, PRECOMMIT, 3, 1, "aa" * 32)
    v2 = make_vote(key, PRECOMMIT, 3, 1, "bb" * 32)
    ev = make_evidence(v1, v2)
    assert evidence_culprit(ev) == key.public_hex
    assert evidence_key(ev) == (key.public_hex, PRECOMMIT, 3, 1)


def test_same_hash_votes_are_not_equivocation():
    key = KeyPair.generate()
    v1 = make_vote(key, PREVOTE, 3, 1, "aa" * 32)
    v2 = make_vote(key, PREVOTE, 3, 1, "aa" * 32)
    assert evidence_culprit(make_evidence(v1, v2)) is None


def test_different_round_votes_are_not_equivocation():
    key = KeyPair.generate()
    v1 = make_vote(key, PREVOTE, 3, 1, "aa" * 32)
    v2 = make_vote(key, PREVOTE, 3, 2, "bb" * 32)
    assert evidence_culprit(make_evidence(v1, v2)) is None


def test_double_proposal_evidence():
    key = KeyPair.generate()
    p1 = make_proposal(key, _block(key, ts=1.0), 0)
    p2 = make_proposal(key, _block(key, ts=2.0), 0)
    assert block_hash(p1["block"]) != block_hash(p2["block"])
    ev = make_evidence(p1, p2)
    assert evidence_culprit(ev) == key.public_hex
    assert evidence_key(ev) == (key.public_hex, "proposal", 1, 0)
