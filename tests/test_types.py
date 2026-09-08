import copy

from blockchain_demo.crypto import AccountKey, KeyPair
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


# ------------------------------------------------------------- transactions
def test_tx_validation():
    key = AccountKey.generate()
    tx = make_tx(key, AccountKey.generate().address, 10, 0)
    assert validate_tx(tx)
    tx["amount"] = 999  # tamper after signing
    assert not validate_tx(tx)


def test_tx_sender_is_address_and_pubkey_binds_it():
    key = AccountKey.generate()
    recipient = AccountKey.generate().address
    tx = make_tx(key, recipient, 10, 0)
    assert tx["sender"] == key.address
    assert tx["recipient"] == recipient


def test_unsigned_tx_rejected():
    key = AccountKey.generate()
    tx = make_tx(key, AccountKey.generate().address, 10, 0)
    # no signature field at all
    assert not validate_tx({k: v for k, v in tx.items() if k != "signature"})
    # empty signature
    no_sig = copy.deepcopy(tx)
    no_sig["signature"] = ""
    assert not validate_tx(no_sig)


def test_signature_by_wrong_key_rejected():
    key = AccountKey.generate()
    other = AccountKey.generate()
    tx = make_tx(key, other.address, 10, 0)
    forged = copy.deepcopy(tx)
    forged["signature"] = other.sign(b"whatever")
    assert not validate_tx(forged)


def test_pubkey_not_matching_sender_rejected():
    key = AccountKey.generate()
    other = AccountKey.generate()
    tx = make_tx(key, other.address, 10, 0)
    # claim key's address but present another account's public key
    tampered = copy.deepcopy(tx)
    tampered["pubkey"] = other.public_hex
    assert not validate_tx(tampered)


def test_tampered_tx_fields_rejected():
    key = AccountKey.generate()
    recipient = AccountKey.generate()
    tx = make_tx(key, recipient.address, 10, 0)
    mutations = {
        "amount": 999,
        "nonce": 7,
        "recipient": "11" * 20,
        "sender": "22" * 20,
        "pubkey": recipient.public_hex,
    }
    for field, value in mutations.items():
        tampered = copy.deepcopy(tx)
        tampered[field] = value
        assert not validate_tx(tampered), f"tampered {field} must be rejected"


def test_tx_shape_validation():
    key = AccountKey.generate()
    to = AccountKey.generate().address
    assert not validate_tx(make_tx(key, to, 0, 0))      # zero amount
    assert not validate_tx(make_tx(key, to, -1, 0))     # negative amount
    assert not validate_tx(make_tx(key, to, 10, -1))    # negative nonce
    # boolean amounts are not valid integers
    tx = make_tx(key, to, 10, 0)
    tx["amount"] = True
    assert not validate_tx(tx)
    # missing fields
    for field in ("sender", "recipient", "amount", "nonce", "pubkey", "signature"):
        partial = {k: v for k, v in make_tx(key, to, 10, 0).items() if k != field}
        assert not validate_tx(partial)


# ------------------------------------------------------------- consensus sigs
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
