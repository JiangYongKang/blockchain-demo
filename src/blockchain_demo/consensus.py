"""Tendermint-style BFT consensus engine.

For each height, rounds of  Propose -> Prevote -> Precommit -> (Commit | next round).

Safety: a block is committed only after >2/3 of total stake precommits it.
Two conflicting blocks can never both reach a >2/3 precommit quorum at the
same height unless >=1/3 of stake equivocates — and equivocation (double
signing) is detected from the votes themselves and slashed on-chain.

Liveness: with >2/3 of stake honest and eventually timely, some round has an
honest proposer and enough honest votes to commit.

All handlers run on the node's single asyncio loop, so no locking is needed.
"""

from __future__ import annotations

import asyncio
import copy
import time
from collections import defaultdict
from typing import TYPE_CHECKING, Optional

from .types import (
    PRECOMMIT,
    PREVOTE,
    block_body_matches_header,
    block_hash,
    make_block,
    make_evidence,
    make_proposal,
    make_vote,
    validate_proposal,
    validate_vote,
)

if TYPE_CHECKING:
    from .node import Node

PROPOSE, PREVOTE_STEP, PRECOMMIT_STEP = "propose", "prevote", "precommit"


class Consensus:
    def __init__(self, node: "Node"):
        self.node = node
        cfg = node.config
        self.timeout_propose = cfg.get("timeout_propose", 2.0)
        self.timeout_prevote = cfg.get("timeout_prevote", 1.0)
        self.timeout_precommit = cfg.get("timeout_precommit", 1.0)

        self.height = -1
        self.round = -1
        self.step = PROPOSE

        # Locking / validity bookkeeping (reset every height).
        self.locked_round = -1
        self.locked_hash: Optional[str] = None
        self.valid_round = -1
        self.valid_hash: Optional[str] = None

        self.proposals: dict[int, dict] = {}            # round -> first proposal seen
        self.proposal_hashes: dict[int, str] = {}       # round -> hash of first proposal (equivocation check)
        self.blocks_by_hash: dict[str, dict] = {}       # hash -> block content
        self.prevotes: dict[int, dict[str, dict]] = defaultdict(dict)    # round -> validator -> vote
        self.precommits: dict[int, dict[str, dict]] = defaultdict(dict)
        self._seen_votes: dict[tuple, Optional[str]] = {}  # (type, round, validator) -> block_hash
        self.pending_commit: Optional[str] = None       # block hash awaiting content
        self._timers: list[asyncio.TimerHandle] = []
        # Messages for the next height that arrived slightly early (a peer
        # committed before us). Replayed when we start that height.
        self._future: list[dict] = []

    # ------------------------------------------------------------------ utils
    @property
    def state(self):
        return self.node.chain_state

    @property
    def me(self) -> str:
        return self.node.pubkey

    def log(self, msg: str) -> None:
        self.node.log(f"consensus h={self.height} r={self.round} {self.step}: {msg}")

    def _schedule(self, delay: float, fn, *args) -> None:
        self._timers.append(asyncio.get_running_loop().call_later(delay, fn, *args))

    def _cancel_timers(self) -> None:
        for t in self._timers:
            t.cancel()
        self._timers.clear()

    def _quorum(self, stake: int) -> bool:
        return stake > self.state.total_stake * 2 / 3

    def _stake_of(self, votes: dict[str, dict], target_hash) -> int:
        return sum(
            self.state.validators.get(v, 0)
            for v, vote in votes.items()
            if vote["block_hash"] == target_hash
        )

    # -------------------------------------------------------------- lifecycle
    # start_height/start_round only QUEUE the transition (via call_soon) and
    # the real work happens in _do_*. This makes every state transition
    # atomic: handlers that trigger a round/height change deep in the call
    # stack (e.g. a vote that completes a quorum inside our own _precommit)
    # can never corrupt the caller's in-flight state.
    def start_height(self, height: int) -> None:
        asyncio.get_running_loop().call_soon(self._do_start_height, height)

    def _do_start_height(self, height: int) -> None:
        if height <= self.height and self.height >= 0:
            return  # stale queued transition
        self.height = height
        self.round = -1
        self.step = PROPOSE
        self.locked_round = -1
        self.locked_hash = None
        self.valid_round = -1
        self.valid_hash = None
        self.proposals.clear()
        self.proposal_hashes.clear()
        self.blocks_by_hash.clear()
        self.prevotes.clear()
        self.precommits.clear()
        self._seen_votes.clear()
        self.pending_commit = None
        future, self._future = self._future, []
        self.start_round(0)
        if future:
            self.log(f"replaying {len(future)} buffered next-height messages")
            for msg in future:
                self.node._on_net_message(msg, None)

    def start_round(self, round_: int) -> None:
        asyncio.get_running_loop().call_soon(self._do_start_round, round_)

    def _do_start_round(self, round_: int) -> None:
        if round_ <= self.round:
            return  # stale queued transition
        self.round = round_
        self.step = PROPOSE
        self._cancel_timers()
        proposer = self.state.proposer_for(self.height, round_)
        self.log(f"new round, proposer={proposer[:8]}")
        if proposer == self.me:
            self._propose()
        self._schedule(self.timeout_propose, self._on_propose_timeout, self.height, round_)
        # A proposal or votes may have arrived before we entered this round.
        if round_ in self.proposals:
            self._maybe_prevote(round_)
        self._check_prevotes(round_)
        self._check_precommits()

    # ---------------------------------------------------------------- propose
    def _propose(self) -> None:
        if self.locked_hash is not None and self.locked_hash in self.blocks_by_hash:
            block = self.blocks_by_hash[self.locked_hash]  # re-propose locked block
        else:
            txs = self.node.mempool_snapshot(limit=100)
            evidence = self.node.evidence_snapshot(limit=10)
            # Compute the post-block state root over a dry-run and commit it in
            # the header. Every honest validator recomputes this and rejects a
            # header whose root does not match the state they derive, so a
            # proposer cannot lie about the resulting state.
            candidate = make_block(
                height=self.height,
                round_=self.round,
                prev_hash=self.node.last_block_hash,
                timestamp=time.time(),
                proposer=self.me,
                txs=txs,
                evidence=evidence,
            )
            app_state_root = self.state.dry_run_block(candidate).state_root()
            block = make_block(
                height=self.height,
                round_=self.round,
                prev_hash=self.node.last_block_hash,
                timestamp=candidate["header"]["timestamp"],
                proposer=self.me,
                txs=txs,
                evidence=evidence,
                app_state_root=app_state_root,
            )
        proposal = make_proposal(self.node.key, block, self.round)
        self.log(f"proposing block {block_hash(block)[:8]} ({len(block['txs'])} txs)")
        self._broadcast({"type": "proposal", "data": proposal})
        self.on_proposal(proposal)
        if self.node.byzantine:
            self._byzantine_double_propose(block)

    def _byzantine_double_propose(self, block: dict) -> None:
        """Byzantine behavior: sign and broadcast a conflicting second proposal."""
        evil = copy.deepcopy(block)
        # Different content -> different hash. Keep the body identical but bump
        # the timestamp; the committed state root stays consistent enough for a
        # second valid-looking proposal (honest nodes still only commit one).
        evil["header"]["timestamp"] = block["header"]["timestamp"] + 0.0001
        proposal = make_proposal(self.node.key, evil, self.round)
        self.log(f"BYZANTINE: double-proposing {block_hash(evil)[:8]}")
        self._broadcast({"type": "proposal", "data": proposal})

    def on_proposal(self, proposal: dict) -> None:
        if not validate_proposal(proposal):
            return
        block = proposal["block"]
        if proposal["height"] == self.height + 1:
            if len(self._future) < 1000:
                self._future.append({"type": "proposal", "data": proposal})
            return
        if proposal["height"] != self.height:
            return
        rnd = proposal["round"]
        if proposal["proposer"] != self.state.proposer_for(self.height, rnd):
            return
        h = block_hash(block)
        prev = self.proposal_hashes.get(rnd)
        if prev is not None and prev != h:
            # Same proposer, same height+round, two different blocks: equivocation.
            self._report_equivocation(self.proposals[rnd], proposal)
        if prev is None:
            self.proposals[rnd] = proposal
            self.proposal_hashes[rnd] = h
        self.blocks_by_hash[h] = block
        if self.pending_commit == h:
            self._commit(h)
        if rnd == self.round and self.step == PROPOSE:
            self._maybe_prevote(rnd)

    def _block_is_valid(self, block: dict) -> bool:
        """Full validity check an honest validator runs before voting for a block.

        The block must (a) have a body whose tx/evidence lists match the Merkle
        roots in its header, and (b) execute cleanly against our state — and the
        state root we derive from executing it MUST equal the `app_state_root`
        the proposer committed in the header. A mismatched root means the
        proposer is lying about the resulting state (or the header was altered),
        so we prevote nil exactly as for an invalid transaction.
        """
        try:
            if not block_body_matches_header(block):
                return False
            post = self.state.dry_run_block(block)
            return post.state_root() == block["header"]["app_state_root"]
        except Exception:
            return False

    def _maybe_prevote(self, round_: int) -> None:
        proposal = self.proposals.get(round_)
        if proposal is None or self.step != PROPOSE:
            return
        h = proposal["block_hash"]
        valid = self._block_is_valid(proposal["block"])
        if not valid:
            self._prevote(None)
        elif self.locked_round == -1 or self.locked_hash == h:
            self._prevote(h)
        elif self.valid_round > self.locked_round and self.valid_hash == h:
            self._prevote(h)  # unlock: newer polka for this block
        else:
            self._prevote(None)
        self.step = PREVOTE_STEP
        self._schedule(self.timeout_prevote, self._on_prevote_timeout, self.height, round_)

    def _on_propose_timeout(self, height: int, round_: int) -> None:
        if height == self.height and round_ == self.round and self.step == PROPOSE:
            self.log("propose timeout -> prevote nil")
            self._prevote(None)
            self.step = PREVOTE_STEP
            self._schedule(self.timeout_prevote, self._on_prevote_timeout, height, round_)

    # ---------------------------------------------------------------- prevote
    def _prevote(self, block_hash_: Optional[str]) -> None:
        self._vote(PREVOTE, block_hash_)
        if self.node.byzantine:
            self._byzantine_double_vote(PREVOTE, block_hash_)

    def _on_prevote_timeout(self, height: int, round_: int) -> None:
        if height == self.height and round_ == self.round and self.step == PREVOTE_STEP:
            self.log("prevote timeout -> precommit nil")
            self._precommit(None)
            self.step = PRECOMMIT_STEP
            self._schedule(self.timeout_precommit, self._on_precommit_timeout, height, round_)

    def _check_prevotes(self, round_: int) -> None:
        votes = self.prevotes[round_]
        for target in {v["block_hash"] for v in votes.values()}:
            if not self._quorum(self._stake_of(votes, target)):
                continue
            if target is None:
                if round_ == self.round and self.step == PREVOTE_STEP:
                    self.log("polka for nil -> precommit nil")
                    self._precommit(None)
                    self.step = PRECOMMIT_STEP
                    self._schedule(
                        self.timeout_precommit, self._on_precommit_timeout, self.height, round_
                    )
            else:
                # Polka for a block: it becomes valid; lock if newer.
                if self.valid_round < round_:
                    self.valid_round, self.valid_hash = round_, target
                if self.locked_round < round_:
                    self.locked_round, self.locked_hash = round_, target
                    self.log(f"locked on {target[:8]}")
                if round_ == self.round and self.step == PREVOTE_STEP:
                    self._precommit(target)
                    self.step = PRECOMMIT_STEP
                    self._schedule(
                        self.timeout_precommit, self._on_precommit_timeout, self.height, round_
                    )

    # -------------------------------------------------------------- precommit
    def _precommit(self, block_hash_: Optional[str]) -> None:
        self._vote(PRECOMMIT, block_hash_)
        if self.node.byzantine:
            self._byzantine_double_vote(PRECOMMIT, block_hash_)

    def _on_precommit_timeout(self, height: int, round_: int) -> None:
        if height == self.height and round_ == self.round:
            self.log("precommit timeout -> next round")
            self.start_round(round_ + 1)

    def _check_precommits(self) -> None:
        # Commit rule: >2/3 precommits for the same block at ANY round of this height.
        for rnd, votes in list(self.precommits.items()):
            for target in {v["block_hash"] for v in votes.values()}:
                if target is not None and self._quorum(self._stake_of(votes, target)):
                    self._commit(target)
                    return
        # No commit yet: if this round is decided (any >2/3 precommits), move on.
        votes = self.precommits.get(self.round, {})
        if votes and self._quorum(sum(self.state.validators.get(v, 0) for v in votes)):
            self.start_round(self.round + 1)

    def _commit(self, target_hash: str) -> None:
        block = self.blocks_by_hash.get(target_hash)
        if block is None:
            self.pending_commit = target_hash
            self.node.request_block(self.height, target_hash)
            return
        commits = [
            vote
            for votes in self.precommits.values()
            for vote in votes.values()
            if vote["block_hash"] == target_hash
        ]
        self.node.commit_block(block, commits)

    # -------------------------------------------------------------------- votes
    def _vote(self, vtype: str, block_hash_: Optional[str]) -> None:
        if not self.state.is_validator(self.me):
            return  # slashed to zero / not a validator: no voting power
        self.log(f"{vtype} for {str(block_hash_)[:8] if block_hash_ else 'nil'}")
        vote = make_vote(self.node.key, vtype, self.height, self.round, block_hash_)
        self._broadcast({"type": "vote", "data": vote})
        self.on_vote(vote)

    def _byzantine_double_vote(self, vtype: str, honest_hash: Optional[str]) -> None:
        """Byzantine behavior: also sign a conflicting vote in the same round."""
        other = next(
            (h for h in self.blocks_by_hash if h != honest_hash),
            "00" * 32 if honest_hash != "00" * 32 else "ff" * 32,
        )
        vote = make_vote(self.node.key, vtype, self.height, self.round, other)
        self.log(f"BYZANTINE: double-{vtype} for {str(other)[:8]}")
        self._broadcast({"type": "vote", "data": vote})

    def on_vote(self, vote: dict) -> None:
        if not validate_vote(vote):
            return
        if vote["height"] == self.height + 1:
            if len(self._future) < 1000:
                self._future.append({"type": "vote", "data": vote})
            return
        if vote["height"] != self.height:
            if vote["height"] > self.height + 1:
                self.node.maybe_sync()
            return
        validator = vote["validator"]
        if not self.state.is_validator(validator):
            return
        key = (vote["type"], vote["round"], validator)
        prev = self._seen_votes.get(key)
        if prev is not None:
            if prev != vote["block_hash"]:
                # Same validator, same type/height/round, two different hashes.
                store = self.prevotes if vote["type"] == PREVOTE else self.precommits
                self._report_equivocation(store[vote["round"]][validator], vote)
            return
        self._seen_votes[key] = vote["block_hash"]
        if vote["type"] == PREVOTE:
            self.prevotes[vote["round"]][validator] = vote
            self._check_prevotes(vote["round"])
        else:
            self.precommits[vote["round"]][validator] = vote
            self._check_precommits()

    # ------------------------------------------------------------- equivocation
    def _report_equivocation(self, item_a: dict, item_b: dict) -> None:
        evidence = make_evidence(item_a, item_b)
        if self.node.add_evidence(evidence):
            self.log(f"EQUIVOCATION detected, evidence broadcast")
            self._broadcast({"type": "evidence", "data": evidence})

    def on_evidence(self, evidence: dict) -> None:
        self.node.add_evidence(evidence)

    def _broadcast(self, msg: dict) -> None:
        self.node.broadcast(msg)
