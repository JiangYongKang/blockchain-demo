"""Core data types: transactions, blocks, votes, proposals, equivocation evidence.

Everything is a plain dict at the wire level; these helpers build, sign,
hash and validate them. Canonical sign-bytes always include the chain id so
signatures cannot be replayed across networks.
"""

from __future__ import annotations

from typing import Any, Optional

from .crypto import KeyPair, canonical, hash_obj, verify

CHAIN_ID = "blockchain-demo-local"

# Vote types (Tendermint-style two-phase voting).
PREVOTE = "prevote"
PRECOMMIT = "precommit"

# Fraction of a double-signing validator's stake that is slashed (1/2).
SLASH_NUM, SLASH_DEN = 1, 2


# ---------------------------------------------------------------- transactions
def make_tx(key: KeyPair, recipient: str, amount: int, nonce: int) -> dict:
    body = {"sender": key.public_hex, "recipient": recipient, "amount": amount, "nonce": nonce}
    tx = dict(body)
    tx["signature"] = key.sign(canonical({"chain_id": CHAIN_ID, "tx": body}))
    return tx


def tx_sign_bytes(tx: dict) -> bytes:
    body = {k: tx[k] for k in ("sender", "recipient", "amount", "nonce")}
    return canonical({"chain_id": CHAIN_ID, "tx": body})


def validate_tx(tx: dict) -> bool:
    try:
        if not isinstance(tx["amount"], int) or tx["amount"] <= 0:
            return False
        if not isinstance(tx["nonce"], int) or tx["nonce"] < 0:
            return False
        return verify(tx["sender"], tx_sign_bytes(tx), tx["signature"])
    except (KeyError, TypeError):
        return False


# ---------------------------------------------------------------------- blocks
def make_block(
    height: int,
    round_: int,
    prev_hash: str,
    timestamp: float,
    proposer: str,
    txs: list[dict],
    evidence: list[dict],
) -> dict:
    return {
        "height": height,
        "round": round_,
        "prev_hash": prev_hash,
        "timestamp": timestamp,
        "proposer": proposer,
        "txs": txs,
        "evidence": evidence,
    }


def block_hash(block: dict) -> str:
    return hash_obj(block)


# ----------------------------------------------------------------------- votes
def make_vote(key: KeyPair, vtype: str, height: int, round_: int, block_hash_: Optional[str]) -> dict:
    body = {
        "type": vtype,
        "height": height,
        "round": round_,
        "block_hash": block_hash_,
        "validator": key.public_hex,
    }
    vote = dict(body)
    vote["signature"] = key.sign(canonical({"chain_id": CHAIN_ID, "vote": body}))
    return vote


def vote_sign_bytes(vote: dict) -> bytes:
    body = {k: vote[k] for k in ("type", "height", "round", "block_hash", "validator")}
    return canonical({"chain_id": CHAIN_ID, "vote": body})


def validate_vote(vote: dict) -> bool:
    try:
        if vote["type"] not in (PREVOTE, PRECOMMIT):
            return False
        if vote["block_hash"] is not None and not isinstance(vote["block_hash"], str):
            return False
        return verify(vote["validator"], vote_sign_bytes(vote), vote["signature"])
    except (KeyError, TypeError):
        return False


# ------------------------------------------------------------------- proposals
def make_proposal(key: KeyPair, block: dict, round_: int) -> dict:
    """Sign a proposal for `block` at the CURRENT round.

    Note the round is passed explicitly: when a validator re-proposes its
    locked block in a later round, the block keeps its original `round`
    field (it is part of the block hash), while the proposal must carry the
    round it is broadcast in.
    """
    body = {"height": block["height"], "round": round_, "block_hash": block_hash(block)}
    return {
        **body,
        "block": block,
        "proposer": key.public_hex,
        "signature": key.sign(canonical({"chain_id": CHAIN_ID, "proposal": body})),
    }


def proposal_sign_bytes(proposal: dict) -> bytes:
    body = {k: proposal[k] for k in ("height", "round", "block_hash")}
    return canonical({"chain_id": CHAIN_ID, "proposal": body})


def validate_proposal(proposal: dict) -> bool:
    try:
        block = proposal["block"]
        if block_hash(block) != proposal["block_hash"]:
            return False
        # The signed height must match the block's own height. The block's
        # `proposer` field is informational only: a validator locked on a
        # block re-proposes the ORIGINAL block (created by someone else) in a
        # later round, signed with its own key — that must remain valid.
        if block["height"] != proposal["height"]:
            return False
        return verify(proposal["proposer"], proposal_sign_bytes(proposal), proposal["signature"])
    except (KeyError, TypeError):
        return False


# --------------------------------------------------------------------- evidence
def make_evidence(item_a: dict, item_b: dict) -> dict:
    """Evidence of equivocation: two conflicting votes or proposals."""
    return {"item_a": item_a, "item_b": item_b}


def _items_conflict(a: dict, b: dict) -> Optional[str]:
    """Return the signer pubkey if a/b prove an equivocation, else None."""
    # Vote equivocation: same validator, type, height, round — different block.
    if "type" in a and "type" in b:
        if (
            a["validator"] == b["validator"]
            and a["type"] == b["type"]
            and a["height"] == b["height"]
            and a["round"] == b["round"]
            and a["block_hash"] != b["block_hash"]
            and validate_vote(a)
            and validate_vote(b)
        ):
            return a["validator"]
        return None
    # Proposal equivocation: same proposer, height, round — different block.
    if (
        a["proposer"] == b["proposer"]
        and a["height"] == b["height"]
        and a["round"] == b["round"]
        and a["block_hash"] != b["block_hash"]
        and validate_proposal(a)
        and validate_proposal(b)
    ):
        return a["proposer"]
    return None


def evidence_culprit(evidence: dict) -> Optional[str]:
    """Return the equivocating validator's pubkey if the evidence is valid."""
    try:
        a, b = evidence["item_a"], evidence["item_b"]
        return _items_conflict(a, b) or _items_conflict(b, a)
    except (KeyError, TypeError):
        return None


def evidence_key(evidence: dict) -> Optional[tuple]:
    """Dedup key: one slash per (culprit, kind, height, round)."""
    culprit = evidence_culprit(evidence)
    if culprit is None:
        return None
    a = evidence["item_a"]
    kind = a.get("type", "proposal")
    return (culprit, kind, a["height"], a["round"])
