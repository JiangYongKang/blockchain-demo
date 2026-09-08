"""Transaction-level adversarial tests.

These prove the state machine and the node admission path refuse every attack
that could let a transaction be replayed, reordered, duplicated or mis-added,
without ever breaking the money-conservation / state-agreement invariants:

  * replay              — the exact same (chain, tx) cannot apply twice;
  * cross-chain replay  — a tx signed for another network is rejected;
  * nonce disorder      — stale / future / gap nonces and two txs spending the
                          same sequence number cannot both execute;
  * duplicate broadcast — re-gossip / re-encoded copies are admitted once and
                          never double-spend, on the mempool and across nodes;
  * overflow / truncation — floats, strings, bools, negatives and absurdly
                          large integer amounts can never reach arithmetic;
  * conservation        — after ANY mix of accepted and rejected txs/evidence,
                          total account balance equals genesis supply and only
                          slashing changes validator stake, and every honest
                          node derives the identical state root.
"""

import asyncio
import copy

import pytest

from blockchain_demo.crypto import AccountKey, KeyPair
from blockchain_demo.node import Node
from blockchain_demo.state import ChainState, MAX_AMOUNT, StateError
from blockchain_demo.types import (
    CHAIN_ID,
    PRECOMMIT,
    block_hash,
    make_block,
    make_evidence,
    make_tx,
    make_vote,
    validate_tx,
)


def _genesis(balance=1_000_000, n_accounts=3, chain_id=CHAIN_ID, n_validators=4):
    vals = [KeyPair.generate() for _ in range(n_validators)]
    accts = [AccountKey.generate() for _ in range(n_accounts)]
    genesis = {
        "chain_id": chain_id,
        "validators": {k.public_hex: 100 for k in vals},
        "balances": {k.address: balance for k in accts},
    }
    return genesis, vals, accts


def _state(balance=1_000_000):
    genesis, vals, accts = _genesis(balance=balance)
    return ChainState(genesis), vals, accts


# =============================================================== conservation
def _total_supply(state: ChainState) -> int:
    return sum(state.balances.values())


def _total_stake(state: ChainState) -> int:
    return sum(state.validators.values())


def test_supply_unchanged_by_rejected_attacks():
    """Every rejected attack leaves total balances and all nonces untouched."""
    state, _, accts = _state(balance=1_000)
    a, b, c = accts
    supply = _total_supply(state)

    attacks = [
        lambda: make_tx(a, b.address, 10, 0),                       # replay
        lambda: make_tx(a, b.address, 10, 5),                       # future nonce
        lambda: make_tx(a, b.address, 10_000, 0),                   # insufficient funds
        lambda: make_tx(a, b.address, 10, -1),                      # negative nonce
    ]
    # First a legitimate tx so nonce is consumed, then attack with replays.
    state.apply_tx(make_tx(a, b.address, 10, 0))
    replay = make_tx(a, b.address, 10, 0)  # same body/signature as the one just applied
    with pytest.raises(StateError):
        state.apply_tx(replay)
    for build in attacks[1:]:
        with pytest.raises(StateError):
            state.apply_tx(build())
    # Malformed shapes that must raise before touching state.
    for bad in [
        {**make_tx(a, b.address, 10, 1), "amount": 10.5},
        {**make_tx(a, b.address, 10, 1), "amount": "10"},
        {**make_tx(a, b.address, 10, 1), "amount": True},
        {**make_tx(a, b.address, 10, 1), "amount": MAX_AMOUNT + 1},
    ]:
        with pytest.raises(StateError):
            state.apply_tx(bad)

    assert _total_supply(state) == supply
    assert state.nonces[a.address] == 1  # only the single good tx advanced the nonce
    assert state.balances[a.address] == 990
    assert state.balances[b.address] == 1010


# =================================================================== replay
def test_same_tx_replay_rejected_in_state_and_block():
    state, _, accts = _state()
    tx = make_tx(accts[0], accts[1].address, 100, 0)
    state.apply_tx(tx)
    # Replay through the raw state machine: nonce already consumed.
    with pytest.raises(StateError):
        state.apply_tx(copy.deepcopy(tx))
    # Replay hidden inside a later block: atomic apply_block rejects the whole
    # block, so nothing in it (even a fresh tx) takes effect.
    block = make_block(
        1, 0, "0" * 64, 1.0, accts[0].address,
        [tx, make_tx(accts[0], accts[1].address, 50, 1)], [],
    )
    with pytest.raises(StateError):
        state.apply_block(block)
    assert state.nonces[accts[0].address] == 1
    assert state.balances[accts[0].address] == 1_000_000 - 100
    assert state.balances[accts[1].address] == 1_000_000 + 100


def test_cross_chain_replay_rejected():
    """A tx signed for a different chain_id cannot be applied on this chain."""
    other_chain = "some-other-network"
    genesis, _, accts = _genesis()
    state = ChainState(genesis)
    # A properly-funded tx from a local account but signed over the OTHER
    # chain's id: valid on its home chain, invalid when replayed here.
    local = accts[0]
    foreign = make_tx(local, accts[1].address, 100, 0, chain_id=other_chain)
    assert validate_tx(foreign, chain_id=other_chain)        # valid on its home chain
    assert not validate_tx(foreign, chain_id=state.chain_id)  # invalid here
    with pytest.raises(StateError):
        state.apply_tx(foreign)
    assert state.balances[accts[0].address] == 1_000_000
    assert state.nonces[accts[0].address] == 0
    # And a state initialised on the other chain accepts it (proves chain bind).
    other = ChainState({**genesis, "chain_id": other_chain})
    other.apply_tx(foreign)
    assert other.balances[accts[1].address] == 1_000_100


# ============================================================= nonce disorder
def test_nonce_disorder_all_rejected():
    state, _, accts = _state(balance=1_000)
    a, b = accts[0], accts[1]
    # Future nonce refused before anything is applied.
    with pytest.raises(StateError):
        state.apply_tx(make_tx(a, b.address, 1, 2))
    state.apply_tx(make_tx(a, b.address, 1, 0))  # now at nonce 1
    for bad_nonce in (0, 3, 99):                  # stale (0) and gaps (3, 99)
        with pytest.raises(StateError):
            state.apply_tx(make_tx(a, b.address, 1, bad_nonce))
    # Negative / bool nonces rejected structurally.
    for nn in (-1, True):
        with pytest.raises(StateError):
            state.apply_tx(make_tx(a, b.address, 1, nn))
    assert state.nonces[a.address] == 1


def test_two_txs_same_nonce_cannot_both_execute():
    """Double-spend: two distinct txs from one sender at the same nonce.

    Only the first can ever apply; the second is a replay-equivalent and is
    rejected by the state machine, inside a block, and by the mempool.
    """
    state, _, accts = _state(balance=1_000)
    a, b, c = accts[0], accts[1], accts[2]
    tx1 = make_tx(a, b.address, 100, 0)
    tx2 = make_tx(a, c.address, 100, 0)  # same sender+nonce, different recipient
    state.apply_tx(tx1)
    with pytest.raises(StateError):
        state.apply_tx(tx2)
    assert state.balances[b.address] == 1_100
    assert state.balances[c.address] == 1_000  # the competing spend never lands

    # A block containing both same-nonce txs is rejected wholesale.
    s2, _, ac2 = _state(balance=1_000)
    blk = make_block(
        1, 0, "0" * 64, 1.0, ac2[0].address,
        [make_tx(ac2[0], ac2[1].address, 100, 0),
         make_tx(ac2[0], ac2[2].address, 100, 0)],
        [],
    )
    with pytest.raises(StateError):
        s2.apply_block(blk)
    assert s2.nonces[ac2[0].address] == 0
    assert s2.balances[ac2[1].address] == 1_000
    assert s2.balances[ac2[2].address] == 1_000


# =============================================== overflow / precision / types
def test_non_integer_and_out_of_range_amounts_rejected():
    state, _, accts = _state(balance=1_000)
    a, b = accts[0], accts[1]
    # A float "amount" truncates to a different value and must not be accepted.
    float_tx = make_tx(a, b.address, 10, 1)
    float_tx["amount"] = 10.999
    with pytest.raises(StateError):
        state.apply_tx(float_tx)
    # String, bool, negative, over-256-bit all rejected.
    for amt in ["100", True, False, -5, MAX_AMOUNT + 1, 10 ** 300]:
        tx = make_tx(a, b.address, 10, 1)
        tx["amount"] = amt
        with pytest.raises(StateError):
            state.apply_tx(tx)
    assert _total_supply(state) == 3_000
    assert state.nonces[a.address] == 0


def test_self_pay_and_whole_balance_conserve_exactly():
    state, _, accts = _state(balance=1_000)
    a, b = accts[0], accts[1]
    # Spend the entire balance: sender to 0, recipient gains exactly that.
    state.apply_tx(make_tx(a, b.address, 1_000, 0))
    assert state.balances[a.address] == 0
    assert state.balances[b.address] == 2_000
    assert _total_supply(state) == 3_000
    # Off-by-one beyond balance is refused (no negative balance, no truncation).
    with pytest.raises(StateError):
        state.apply_tx(make_tx(b, a.address, 2_001, 0))
    assert state.balances[b.address] == 2_000


# =================================================================== slashing
def test_slashing_reduces_only_stake_and_is_idempotent():
    genesis, vals, _ = _genesis(balance=1_000)
    state = ChainState(genesis)
    bad = vals[0]
    supply = _total_supply(state)
    stake_before = _total_stake(state)
    ev = make_evidence(
        make_vote(bad, PRECOMMIT, 1, 0, "aa" * 32),
        make_vote(bad, PRECOMMIT, 1, 0, "bb" * 32),
    )
    state.apply_evidence(ev)
    state.apply_evidence(ev)  # duplicate evidence must not slash twice
    assert len(state.slashed) == 1
    assert state.validators[bad.public_hex] == 50
    # Slashing touches validator STAKE, never account balances.
    assert _total_supply(state) == supply
    assert _total_stake(state) == stake_before - 50
    # Invalid / non-conflicting evidence rejected without effect.
    v = make_vote(vals[1], PRECOMMIT, 2, 0, "cc" * 32)
    with pytest.raises(StateError):
        state.apply_evidence(make_evidence(v, v))
    assert _total_stake(state) == stake_before - 50


# ------------------------------------------------------- node/mempool admission
def _make_nodes(tmp_path, n=4, accts=None, balance=1_000_000, byzantine=()):
    import json as _json

    keys = [KeyPair.generate() for _ in range(n)]
    if accts is None:
        accts = [AccountKey.generate() for _ in range(3)]
    genesis = {
        "chain_id": CHAIN_ID,
        "validators": {k.public_hex: 100 for k in keys},
        "balances": {a.address: balance for a in accts},
    }
    configs = []
    for i in range(n):
        cfg = {"node_id": i, "host": "127.0.0.1", "p2p_port": 0, "rpc_port": 0,
               "byzantine": i in byzantine}
        configs.append(cfg)
        d = tmp_path / f"node{i}"
        d.mkdir(exist_ok=True)
        (d / "config.json").write_text(_json.dumps(cfg))
        (d / "key.json").write_text(_json.dumps(keys[i].to_dict()))
    nodes = [Node(tmp_path / f"node{i}", configs, genesis) for i in range(n)]
    for node in nodes:
        node.log = lambda *a, **k: None
    return nodes, accts


def test_mempool_dedup_by_sender_nonce_and_chain(tmp_path):
    nodes, accts = _make_nodes(tmp_path)
    node = nodes[0]
    a, b, c = accts[0], accts[1], accts[2]
    tx = make_tx(a, b.address, 100, 0)
    ok, _ = node.add_tx(tx)
    assert ok
    # Exact duplicate broadcast: refused (already pending).
    ok, reason = node.add_tx(copy.deepcopy(tx))
    assert not ok and "duplicate" in reason
    # Re-encoded/malleated copy: same sender+nonce but a fresh valid signature
    # over the identical body (ECDSA is randomized, signature bytes differ).
    malleated = make_tx(a, b.address, 100, 0)
    assert malleated["signature"] != tx["signature"]
    ok, reason = node.add_tx(malleated)
    assert not ok and "duplicate" in reason
    # A competing same-nonce spend to a different recipient is also refused.
    ok, reason = node.add_tx(make_tx(a, c.address, 100, 0))
    assert not ok
    # Cross-chain tx (wrong chain_id) refused at admission.
    foreign = make_tx(accts[2], b.address, 10, 0, chain_id="other-net")
    ok, reason = node.add_tx(foreign)
    assert not ok and "chain" in reason
    assert len(node.mempool) == 1


def test_mempool_evicts_stale_nonce_after_commit(tmp_path):
    nodes, accts = _make_nodes(tmp_path, balance=1_000)
    node = nodes[0]
    node.consensus.start_height = lambda _h: None  # sync test: no running loop
    a, b, c = accts[0], accts[1], accts[2]
    winner = make_tx(a, b.address, 100, 0)
    loser = make_tx(a, c.address, 100, 0)  # same nonce; arrives but loses the slot
    assert node.add_tx(winner)[0]
    # Simulate the same-nonce competitor already being in the pool (e.g. it
    # arrived on another node first) and then the winner getting committed.
    node.mempool.append(loser)
    base = make_block(
        node.height, 0, node.last_block_hash, 1.0, node.pubkey, [winner], []
    )
    block = make_block(
        node.height, 0, node.last_block_hash, 1.0, node.pubkey, [winner], [],
        app_state_root=node.chain_state.dry_run_block(base).state_root(),
    )
    node.commit_block(block, [])
    assert node.height == 1  # the block was actually committed
    # The loser (stale nonce) must be gone: it can never execute now.
    assert all(t["nonce"] == node.chain_state.nonces.get(t["sender"], 0) for t in node.mempool)
    assert loser not in node.mempool
    # Re-broadcasting the committed tx after finalization is rejected (replay).
    ok, reason = node.add_tx(copy.deepcopy(winner))
    assert not ok and "nonce" in reason


# --------------------------------------------- end-to-end: attack over gossip
class _Hub:
    """In-process async message bus standing in for TCP gossip."""

    def __init__(self, nodes):
        self.nodes = nodes
        self.queue = asyncio.Queue()
        for node in nodes:
            node.broadcast = self._make_broadcast(node)

    def _make_broadcast(self, sender):
        def broadcast(msg):
            for node in self.nodes:
                if node is not sender:
                    self.queue.put_nowait((node, msg))
        return broadcast

    async def run(self):
        while True:
            node, msg = await self.queue.get()
            node._on_net_message(msg, None)
            await asyncio.sleep(0)


def test_replayed_and_duplicate_txs_finalize_once_across_nodes(tmp_path):
    async def main():
        nodes, accts = _make_nodes(tmp_path, n=4, balance=1_000_000)
        a, b = accts[0], accts[1]
        hub = _Hub(nodes)
        for node in nodes:
            node.consensus.start_height(node.height)
        runner = asyncio.create_task(hub.run())

        tx = make_tx(a, b.address, 500, 0)
        try:
            # Flood the SAME tx at every node, repeatedly (duplicate broadcast +
            # replay from multiple peers).
            for _ in range(3):
                for node in nodes:
                    node.add_tx(copy.deepcopy(tx))

            async def settled():
                while not all(
                    nd.chain_state.nonces.get(a.address, 0) == 1
                    and nd.chain_state.balances.get(b.address, 1_000_000) == 1_000_500
                    for nd in nodes
                ):
                    await asyncio.sleep(0.02)

            await asyncio.wait_for(settled(), timeout=20)

            # Invariant 1: identical finalized blocks at every shared height.
            common = min(n.height for n in nodes)
            for h in range(common):
                hashes = {block_hash(n.blocks[h]) for n in nodes}
                assert len(hashes) == 1
            # Invariant 2: identical state root + balances/nonces on all nodes.
            roots = {n.chain_state.state_root() for n in nodes}
            assert len(roots) == 1
            for nd in nodes:
                assert nd.chain_state.balances[a.address] == 999_500
                assert nd.chain_state.balances[b.address] == 1_000_500
                assert nd.chain_state.nonces[a.address] == 1
                assert _total_supply(nd.chain_state) == 3_000_000
        finally:
            runner.cancel()

    asyncio.run(main())
