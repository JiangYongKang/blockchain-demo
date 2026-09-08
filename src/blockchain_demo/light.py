"""Light client: verify finality and state proofs with no trusted node.

A light client stores only what it can check cryptographically:

* a set of **validator public keys** (and their stake) it trusts — e.g. the
  genesis validator set;
* **block headers**, not full blocks.

Given a header, the >2/3 **precommit votes** that finalize it, and a Merkle
**proof** for the value it cares about, it can independently decide:

1. **Finality** — the header is for a committed block: more than 2/3 of the
   stake (weighted by the trusted validator set) signed valid Ed25519 precommit
   votes over `hash(header)` at that height.
2. **Account state** — an account's balance / nonce / code / storage root: the
   header commits `app_state_root`; an account inclusion proof binds the
   account leaf (which encodes those fields) to that root.
3. **Contract storage** — a storage slot: the account proof binds the
   contract's `storage_root`, and a second inclusion proof binds the slot's
   32-byte word to that root.

It never asks a node "what is the balance?" and trusts the answer — it asks
for a *proof* and checks the math. A correct proof always verifies; any
tampering with the balance, the slot value, or a proof hash fails verification;
and no proof can be forged for an account or slot that the state root does not
commit (that would require a SHA-256 collision).
"""

from __future__ import annotations

import json
from typing import Optional

from .merkle import SparseMerkleTree
from .types import PRECOMMIT, block_hash, validate_vote


class LightClientError(Exception):
    pass


# ------------------------------------------------------------------ finality
def verify_finality(header: dict, commits: list[dict], validators: dict[str, int]) -> bool:
    """Return True iff >2/3 of stake precommitted `hash(header)` at its height.

    `validators` maps trusted validator public keys -> stake. Every vote must
    be a valid Ed25519 precommit, at the header's height, for exactly the hash
    of the header; duplicate validators count once. The light client needs the
    header and the votes — never the block body or the node's state.
    """
    try:
        target = block_hash({"header": header, "txs": [], "evidence": []})
    except (KeyError, TypeError):
        return False
    total = sum(validators.values())
    stake = 0
    seen: set[str] = set()
    for vote in commits:
        if not validate_vote(vote):
            return False
        if vote.get("type") != PRECOMMIT:
            return False
        if vote.get("height") != header.get("height"):
            return False
        if vote.get("block_hash") != target:
            return False
        v = vote["validator"]
        if v in seen:
            return False  # a validator gets one vote; duplicates are invalid
        seen.add(v)
        stake += validators.get(v, 0)  # untrusted/unknown validator carries no weight
    return stake > total * 2 / 3


# -------------------------------------------------------------- account proof
def verify_account_proof(state_root: str, proof: dict) -> Optional[dict]:
    """Verify an account inclusion/absence proof against `state_root`.

    Returns the account state `{exists, balance, nonce, code, storage_root}`
    bound by the proof, or None if the proof is invalid. `exists=False` means
    the state root provably contains no such account (balance/nonce are 0).
    """
    try:
        if proof.get("kind") != "account":
            return None
        key, value = proof["key"], proof["value"]
        if not SparseMerkleTree.verify_proof(state_root, key, value, proof["proof"]):
            return None
        if value == "":
            return {"exists": False, "balance": 0, "nonce": 0, "code": "", "storage_root": ""}
        leaf = json.loads(value)
        # Path binding: the proof key must be the hash of the claimed address,
        # so a proof for one address can never be presented for another.
        from .state import account_key

        if account_key(proof["address"]) != key:
            return None
        return {
            "exists": True,
            "balance": leaf["balance"],
            "nonce": leaf["nonce"],
            "code": leaf.get("code", ""),
            "storage_root": leaf["storage_root"],
        }
    except (KeyError, TypeError, ValueError):
        return None


# -------------------------------------------------------------- storage proof
def verify_storage_proof(state_root: str, proof: dict) -> Optional[dict]:
    """Verify a contract storage-slot proof against `state_root`.

    Chains two proofs: the account proof binds the contract's `storage_root`
    to `state_root`, and the slot proof binds the 32-byte word to that storage
    root. Returns `{exists, value}` with `value` the 32-byte hex word ("0x.."-
    free), or None if either proof is invalid.
    """
    try:
        if proof.get("kind") != "storage":
            return None
        account = verify_account_proof(state_root, proof["account"])
        if account is None or not account["exists"]:
            return None
        storage_root = account["storage_root"]
        if storage_root != proof["storage_root"]:
            return None  # the slot proof must sit under the root the account commits
        slot, value = proof["slot"], proof["value"]
        if not SparseMerkleTree.verify_proof(storage_root, slot, value, proof["proof"]):
            return None
        return {
            "exists": value != "",
            "slot": slot,
            "value": value if value != "" else "0" * 64,
        }
    except (KeyError, TypeError, ValueError):
        return None


# ------------------------------------------------------------ one-shot checks
def verify_account(
    header: dict, commits: list[dict], validators: dict[str, int], address: str, proof: dict
) -> Optional[dict]:
    """Full light-client check for an account: finality + inclusion proof."""
    if not verify_finality(header, commits, validators):
        return None
    if proof.get("address") != address:
        return None
    return verify_account_proof(header["app_state_root"], proof)


def verify_storage(
    header: dict,
    commits: list[dict],
    validators: dict[str, int],
    address: str,
    slot,
    proof: dict,
) -> Optional[dict]:
    """Full light-client check for a storage slot: finality + chained proofs."""
    if not verify_finality(header, commits, validators):
        return None
    if proof.get("address") != address:
        return None
    want = _slot_word(slot)
    if proof.get("slot") != want:
        return None
    return verify_storage_proof(header["app_state_root"], proof)


def _slot_word(slot) -> str:
    """Normalize a slot (int, decimal/0x-hex string, or a 32-byte hex word)."""
    if isinstance(slot, int):
        return format(slot, "064x")
    s = slot.strip()
    if s.lower().startswith("0x") or len(s) == 64:  # already a hex word
        return format(int(s, 16), "064x")
    return format(int(s, 0), "064x")  # decimal (or 0x-prefixed)
