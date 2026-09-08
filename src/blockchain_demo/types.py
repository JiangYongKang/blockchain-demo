"""Core data types: transactions, blocks, votes, proposals, equivocation evidence.

Everything is a plain dict at the wire level; these helpers build, sign,
hash and validate them. Canonical sign-bytes always include the chain id so
signatures cannot be replayed across networks.

* Transactions are **account model** transfers signed with **secp256k1
  ECDSA** (`AccountKey`): the tx carries the sender's public key, the sender
  address is derived from it, and the signature proves ownership.
* Consensus messages (votes/proposals) are signed by validators with
  Ed25519 (`KeyPair`).
"""

from __future__ import annotations

from typing import Any, Optional

from .crypto import (
    AccountKey,
    KeyPair,
    address_from_pubkey,
    canonical,
    hash_obj,
    verify,
    verify_ecdsa,
)
from .merkle import merkle_root

CHAIN_ID = "blockchain-demo-local"

# Vote types (Tendermint-style two-phase voting).
PREVOTE = "prevote"
PRECOMMIT = "precommit"

# Fraction of a double-signing validator's stake that is slashed (1/2).
SLASH_NUM, SLASH_DEN = 1, 2

# Transaction kinds. A **transfer** moves funds between externally-owned
# accounts; a **deploy** creates a contract account (with code); a **call**
# invokes a contract, optionally transferring value and/or writing storage.
TRANSFER = "transfer"
DEPLOY = "deploy"
CALL = "call"
TX_KINDS = (TRANSFER, DEPLOY, CALL)


# ---------------------------------------------------------------- transactions
def _sign_tx(key: AccountKey, body: dict, chain_id: str = CHAIN_ID) -> dict:
    tx = dict(body)
    tx["signature"] = key.sign(canonical({"chain_id": chain_id, "tx": body}))
    return tx


def make_tx(key: AccountKey, recipient: str, amount: int, nonce: int, chain_id: str = CHAIN_ID) -> dict:
    """Build a signed **transfer** transaction.

    `sender` is the signer's account address (derived from its public key);
    the public key is embedded so any node can derive the address and verify
    the ECDSA signature without prior knowledge of the account.

    `chain_id` binds the signature to one network (default: this chain). A
    transaction signed for a different chain_id cannot be replayed here.
    """
    body = {
        "kind": TRANSFER,
        "sender": key.address,
        "recipient": recipient,
        "amount": amount,
        "nonce": nonce,
        "pubkey": key.public_hex,
    }
    return _sign_tx(key, body, chain_id)


def make_deploy_tx(key: AccountKey, code_hex: str, nonce: int, chain_id: str = CHAIN_ID) -> dict:
    """Build a signed **contract-deployment** transaction.

    The contract's address is derived deterministically from the creator and
    its account nonce at application time (see `contract.contract_address`);
    the deployed `code_hex` is stored on that new contract account.
    """
    body = {
        "kind": DEPLOY,
        "sender": key.address,
        "code": code_hex,
        "nonce": nonce,
        "pubkey": key.public_hex,
    }
    return _sign_tx(key, body, chain_id)


def make_call_tx(
    key: AccountKey,
    contract: str,
    nonce: int,
    calldata: int = 0,
    amount: int = 0,
    chain_id: str = CHAIN_ID,
) -> dict:
    """Build a signed **contract-call** transaction.

    `calldata` is a single word pushed onto the VM stack (e.g. the value to
    store in a counter); `amount` is an optional value transfer to the
    contract. The contract code runs against its storage during application.
    """
    body = {
        "kind": CALL,
        "sender": key.address,
        "contract": contract,
        "calldata": calldata,
        "amount": amount,
        "nonce": nonce,
        "pubkey": key.public_hex,
    }
    return _sign_tx(key, body, chain_id)


def tx_kind(tx: dict) -> str:
    return tx.get("kind", TRANSFER)


def tx_sign_bytes(tx: dict, chain_id: str = CHAIN_ID) -> bytes:
    """Canonical bytes covered by the ECDSA signature, per transaction kind.

    `chain_id` binds a transaction to one network: the signed payload includes
    it, so a tx from another chain (or replayed against this one) fails
    verification.
    """
    kind = tx_kind(tx)
    if kind == DEPLOY:
        fields = ("kind", "sender", "code", "nonce", "pubkey")
    elif kind == CALL:
        fields = ("kind", "sender", "contract", "calldata", "amount", "nonce", "pubkey")
    else:  # transfer
        fields = ("kind", "sender", "recipient", "amount", "nonce", "pubkey")
    body = {f: tx[f] for f in fields if f in tx}
    return canonical({"chain_id": chain_id, "tx": body})


def _is_int(x) -> bool:
    return isinstance(x, int) and not isinstance(x, bool)


def validate_tx(tx: dict, chain_id: str = CHAIN_ID) -> bool:
    """Structural + ECDSA signature validation for a transaction.

    State-dependent checks (nonce match, sufficient balance, contract
    existence / successful execution) are enforced separately by the state
    machine; this covers everything verifiable without state: well-formed
    fields per kind, a valid secp256k1 public key bound to `sender`, and a
    valid low-S ECDSA signature over chain_id + the tx body.

    The signature is checked against `chain_id`: a transaction signed for a
    different network (a cross-chain replay) carries a signature over a
    different chain_id and is rejected here.
    """
    try:
        kind = tx_kind(tx)
        if kind not in TX_KINDS:
            return False
        # Common shape.
        for f in ("sender", "pubkey", "signature"):
            if not isinstance(tx.get(f), str) or not tx[f]:
                return False
        if not _is_int(tx.get("nonce")) or tx["nonce"] < 0:
            return False
        # The embedded public key must hash to the claimed sender address.
        if address_from_pubkey(tx["pubkey"]) != tx["sender"]:
            return False
        # Per-kind shape.
        if kind == TRANSFER:
            if not _is_int(tx.get("amount")) or tx["amount"] <= 0:
                return False
            if not isinstance(tx.get("recipient"), str) or not tx["recipient"]:
                return False
        elif kind == DEPLOY:
            if not isinstance(tx.get("code"), str) or not tx["code"]:
                return False
            bytes.fromhex(tx["code"])  # must be valid hex bytecode
        else:  # call
            if not isinstance(tx.get("contract"), str) or not tx["contract"]:
                return False
            if not _is_int(tx.get("calldata", 0)) or tx["calldata"] < 0:
                return False
            if not _is_int(tx.get("amount", 0)) or tx["amount"] < 0:
                return False
        # The ECDSA signature must verify against that public key, over this chain.
        return verify_ecdsa(tx["pubkey"], tx_sign_bytes(tx, chain_id), tx["signature"])
    except (KeyError, TypeError, ValueError):
        return False


# ---------------------------------------------------------------------- blocks
# Fields hashed into the block identity (the "block header"). The body — the
# full transaction and evidence lists — is NOT hashed directly; instead the
# header commits to `txs_root` / `evidence_root` (Merkle roots over those
# lists) and to `app_state_root` (the state trie root AFTER applying the
# block). A light client therefore needs only the header to identify the block
# and the state it finalizes, plus Merkle proofs for any account/storage value
# it wants to read.
HEADER_FIELDS = (
    "height",
    "round",
    "prev_hash",
    "timestamp",
    "proposer",
    "txs_root",
    "evidence_root",
    "app_state_root",
)


def make_block(
    height: int,
    round_: int,
    prev_hash: str,
    timestamp: float,
    proposer: str,
    txs: list[dict],
    evidence: list[dict],
    app_state_root: str = "",
) -> dict:
    """Build a block.

    `app_state_root` is the state trie root after applying `txs`/`evidence`;
    the proposer computes it over a dry-run and places it in the header. The
    header also binds Merkle roots over the tx and evidence lists, so the body
    cannot be altered without changing the block hash.
    """
    header = {
        "height": height,
        "round": round_,
        "prev_hash": prev_hash,
        "timestamp": timestamp,
        "proposer": proposer,
        "txs_root": merkle_root([hash_obj(tx) for tx in txs]),
        "evidence_root": merkle_root([hash_obj(ev) for ev in evidence]),
        "app_state_root": app_state_root,
    }
    return {"header": header, "txs": txs, "evidence": evidence}


def block_header(block: dict) -> dict:
    return block["header"]


def block_hash(block: dict) -> str:
    """The block identity is the hash of its header only.

    The header commits to the body via Merkle roots and to the resulting state
    via `app_state_root`, so hashing the header binds everything.
    """
    return hash_obj({k: block["header"][k] for k in HEADER_FIELDS})


def block_body_matches_header(block: dict) -> bool:
    """Check that the tx/evidence bodies match the roots in the header."""
    h = block["header"]
    return (
        h.get("txs_root") == merkle_root([hash_obj(tx) for tx in block.get("txs", [])])
        and h.get("evidence_root")
        == merkle_root([hash_obj(ev) for ev in block.get("evidence", [])])
    )


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
    body = {"height": block["header"]["height"], "round": round_, "block_hash": block_hash(block)}
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
        if block["header"]["height"] != proposal["height"]:
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
