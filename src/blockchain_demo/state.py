"""Chain state: account balances/nonces, validator stakes, block application,
and slashing of equivocating validators.

State transitions happen only at commit time, so every honest node that
commits the same block derives the identical state.
"""

from __future__ import annotations

from .types import (
    SLASH_DEN,
    SLASH_NUM,
    evidence_culprit,
    evidence_key,
    validate_tx,
)

GENESIS_STAKE = 100
GENESIS_BALANCE = 1_000_000


class StateError(Exception):
    pass


class ChainState:
    def __init__(self, genesis: dict):
        self.balances: dict[str, int] = dict(genesis["balances"])
        self.nonces: dict[str, int] = {addr: 0 for addr in self.balances}
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

    # ------------------------------------------------------------- execution
    def apply_tx(self, tx: dict) -> None:
        if not validate_tx(tx):
            raise StateError("invalid transaction signature/shape")
        sender, recipient, amount, nonce = (
            tx["sender"], tx["recipient"], tx["amount"], tx["nonce"],
        )
        if nonce != self.nonces.get(sender, 0):
            raise StateError(f"bad nonce: want {self.nonces.get(sender, 0)}, got {nonce}")
        if self.balances.get(sender, 0) < amount:
            raise StateError("insufficient funds")
        self.balances[sender] -= amount
        self.balances[recipient] = self.balances.get(recipient, 0) + amount
        self.nonces[sender] = nonce + 1

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
        signature / nonce / funds) is rejected with no partial effect, so a
        credit can never land without its matching debit being committed in
        the same accepted block. Honest nodes therefore derive identical
        state from identical blocks.
        """
        import copy

        scratch = copy.deepcopy(self)
        for tx in block["txs"]:
            scratch.apply_tx(tx)
        for ev in block["evidence"]:
            scratch.apply_evidence(ev)
        self.balances = scratch.balances
        self.nonces = scratch.nonces
        self.validators = scratch.validators
        self.slashed = scratch.slashed
        self._seen_evidence = scratch._seen_evidence

    def dry_run_block(self, block: dict) -> "ChainState":
        """Return a copy with the block applied; raises StateError if invalid."""
        import copy

        clone = copy.deepcopy(self)
        clone.apply_block(block)
        return clone
