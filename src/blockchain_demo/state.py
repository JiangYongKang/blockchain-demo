"""Chain state: accounts (EOAs and contracts), validator stakes, block
application, slashing, and the state commitment + inclusion proofs.

State transitions happen only at commit time, so every honest node that
commits the same block derives the identical state — including the identical
**state root**.

Accounts
--------
Every account is an entry with a `balance` and `nonce`. A **contract account**
additionally has `code` (hex bytecode) and `storage` (a map of 32-byte slot
key -> 32-byte value). The whole account set is committed by a sparse Merkle
trie (`state_root`): each account address maps to a leaf encoding its balance,
nonce, code and the root of its *own* storage trie. A contract storage slot is
thus committed twice-over: the storage trie root sits inside the account leaf,
which sits under the state root. Light clients verify a balance with one
Merkle proof and a storage slot with two (account proof + storage proof).
"""

from __future__ import annotations

from .contract import ContractError, contract_address, run_code
from .crypto import canonical, sha256_hex
from .merkle import SparseMerkleTree
from .types import (
    CALL,
    DEPLOY,
    SLASH_DEN,
    SLASH_NUM,
    TRANSFER,
    evidence_culprit,
    evidence_key,
    tx_kind,
    validate_tx,
)

GENESIS_STAKE = 100
GENESIS_BALANCE = 1_000_000


class StateError(Exception):
    pass


# --------------------------------------------------------------- trie helpers
def account_key(address: str) -> str:
    """Trie key for an account address: 256-bit SHA-256 of the address."""
    return sha256_hex(address.encode())


class ChainState:
    def __init__(self, genesis: dict):
        self.balances: dict[str, int] = dict(genesis["balances"])
        self.nonces: dict[str, int] = {addr: 0 for addr in self.balances}
        # Contract accounts only: address -> bytecode hex, and address -> storage.
        self.codes: dict[str, str] = {}
        self.storages: dict[str, dict[str, str]] = {}
        # validator pubkey -> stake (voting power)
        self.validators: dict[str, int] = dict(genesis["validators"])
        self.slashed: list[dict] = []          # audit log of slash events
        self._seen_evidence: set[tuple] = set()  # dedup: one slash per equivocation

    # ------------------------------------------------------------ validators
    @property
    def total_stake(self) -> int:
        return sum(self.validators.values())

    @property
    def quorum(self) -> int:
        """Stake strictly greater than 2/3 of total is a quorum."""
        return self.total_stake * 2 // 3 + 1

    def is_validator(self, pubkey: str) -> bool:
        return self.validators.get(pubkey, 0) > 0

    def active_validators(self) -> list[str]:
        """Validators with voting power, sorted for deterministic proposer choice."""
        return sorted(pub for pub, stake in self.validators.items() if stake > 0)

    def proposer_for(self, height: int, round_: int) -> str:
        active = self.active_validators()
        return active[(height + round_) % len(active)]

    # ------------------------------------------------------------- accounts
    def _all_addresses(self) -> set[str]:
        return set(self.balances) | set(self.nonces) | set(self.codes)

    def storage_root(self, address: str) -> str:
        """Merkle root of a contract's storage trie (empty root for non-contracts)."""
        return SparseMerkleTree(self.storages.get(address, {})).root()

    def account_leaf_value(self, address: str) -> str:
        """Canonical leaf string committed for an account, or "" if absent.

        The leaf binds balance, nonce, code and the storage trie root. A light
        client that verifies this leaf against the state root trusts all four.
        """
        if address not in self._all_addresses():
            return ""
        return canonical(
            {
                "balance": self.balances.get(address, 0),
                "nonce": self.nonces.get(address, 0),
                "code": self.codes.get(address, ""),
                "storage_root": self.storage_root(address),
            }
        ).decode()

    def _account_tree(self) -> SparseMerkleTree:
        return SparseMerkleTree(
            {account_key(addr): self.account_leaf_value(addr) for addr in self._all_addresses()}
        )

    def state_root(self) -> str:
        """The 256-bit sparse-Merkle commitment to the entire account/storage state."""
        return self._account_tree().root()

    # -------------------------------------------------------------- proofs
    def account_proof(self, address: str) -> dict:
        """Build an inclusion (or absence) proof for an account under state_root."""
        tree = self._account_tree()
        key = account_key(address)
        value = self.account_leaf_value(address)
        return {
            "kind": "account",
            "address": address,
            "key": key,
            "value": value,
            "proof": tree.prove(key),
            "root": tree.root(),
        }

    def storage_proof(self, address: str, slot: str) -> dict:
        """Build a proof for a contract storage slot.

        Returns the storage-slot proof plus the account proof, so a light
        client can chain: state_root -> account leaf (binds storage_root) ->
        slot value. `slot` is normalized to a 32-byte word.
        """
        from .contract import word_hex

        slot_key = word_hex(int(slot, 16) if isinstance(slot, str) else slot)
        storage = self.storages.get(address, {})
        tree = SparseMerkleTree(storage)
        return {
            "kind": "storage",
            "address": address,
            "slot": slot_key,
            "value": storage.get(slot_key, ""),
            "proof": tree.prove(slot_key),
            "storage_root": tree.root(),
            "account": self.account_proof(address),
        }

    # ------------------------------------------------------------- execution
    def apply_tx(self, tx: dict) -> None:
        if not validate_tx(tx):
            raise StateError("invalid transaction signature/shape")
        kind = tx_kind(tx)
        sender, nonce = tx["sender"], tx["nonce"]
        if nonce != self.nonces.get(sender, 0):
            raise StateError(f"bad nonce: want {self.nonces.get(sender, 0)}, got {nonce}")

        if kind == TRANSFER:
            self._apply_transfer(sender, tx["recipient"], tx["amount"])
        elif kind == DEPLOY:
            self._apply_deploy(sender, tx["code"])
        elif kind == CALL:
            self._apply_call(sender, tx["contract"], tx.get("calldata", 0), tx.get("amount", 0))
        else:  # unreachable: validate_tx rejects unknown kinds
            raise StateError(f"unknown tx kind {kind!r}")
        self.nonces[sender] = nonce + 1

    def _apply_transfer(self, sender: str, recipient: str, amount: int) -> None:
        if self.balances.get(sender, 0) < amount:
            raise StateError("insufficient funds")
        self.balances[sender] = self.balances.get(sender, 0) - amount
        self.balances[recipient] = self.balances.get(recipient, 0) + amount

    def _apply_deploy(self, sender: str, code: str) -> None:
        addr = contract_address(sender, self.nonces.get(sender, 0))
        if addr in self.codes or addr in self.balances:
            raise StateError("contract address collision")
        self.codes[addr] = code
        self.storages[addr] = {}
        # The new contract account exists (balance 0, nonce 0); record it.
        self.balances.setdefault(addr, 0)

    def _apply_call(self, sender: str, contract: str, calldata: int, amount: int) -> None:
        if contract not in self.codes:
            raise StateError("call to non-existent contract")
        if amount < 0 or self.balances.get(sender, 0) < amount:
            raise StateError("insufficient funds")
        # Execute against a scratch storage copy so a faulting call writes nothing.
        import copy

        storage = copy.deepcopy(self.storages.get(contract, {}))
        try:
            run_code(self.codes[contract], storage, calldata)
        except ContractError as exc:
            raise StateError(f"contract execution failed: {exc}") from exc
        self.storages[contract] = storage
        if amount:
            self.balances[sender] = self.balances.get(sender, 0) - amount
            self.balances[contract] = self.balances.get(contract, 0) + amount

    def apply_evidence(self, evidence: dict) -> None:
        """Slash a proven equivocator. Deterministic; idempotent per equivocation."""
        key = evidence_key(evidence)
        culprit = evidence_culprit(evidence)
        if key is None or culprit is None:
            raise StateError("invalid evidence")
        if key in self._seen_evidence:
            return  # already slashed for this equivocation
        if culprit not in self.validators:
            return  # not (or no longer) a validator
        self._seen_evidence.add(key)
        stake = self.validators[culprit]
        if stake == 0:
            return  # already slashed to zero; nothing left to take
        penalty = max(1, stake * SLASH_NUM // SLASH_DEN)
        self.validators[culprit] = max(0, stake - penalty)
        self.slashed.append(
            {
                "validator": culprit,
                "penalty": min(penalty, stake),
                "remaining": self.validators[culprit],
                "kind": key[1],
                "height": key[2],
                "round": key[3],
            }
        )

    def apply_block(self, block: dict) -> None:
        """Apply a whole block **atomically**.

        Every transaction and piece of evidence is first executed against a
        scratch copy; the resulting state is adopted only if ALL of them
        succeed. A block containing even one invalid transaction (bad
        signature / nonce / funds / contract fault) is rejected with no
        partial effect, so a credit can never land without its matching debit
        being committed in the same accepted block. Honest nodes therefore
        derive identical state — and an identical state root — from identical
        blocks.
        """
        import copy

        scratch = copy.deepcopy(self)
        for tx in block["txs"]:
            scratch.apply_tx(tx)
        for ev in block["evidence"]:
            scratch.apply_evidence(ev)
        self.balances = scratch.balances
        self.nonces = scratch.nonces
        self.codes = scratch.codes
        self.storages = scratch.storages
        self.validators = scratch.validators
        self.slashed = scratch.slashed
        self._seen_evidence = scratch._seen_evidence

    def dry_run_block(self, block: dict) -> "ChainState":
        """Return a copy with the block applied; raises StateError if invalid."""
        import copy

        clone = copy.deepcopy(self)
        clone.apply_block(block)
        return clone
