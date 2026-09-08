"""In-process consensus tests: 4 validators over a virtual hub (no real TCP).

Covers the BFT requirements:
  * honest nodes finalize the same block at every height;
  * the chain keeps progressing with 1 of 4 validators down (f < n/3);
  * a double-signing validator is detected and slashed on-chain;
  * no two conflicting blocks are ever finalized at the same height.
"""

import asyncio
import json

import pytest

from blockchain_demo.crypto import KeyPair
from blockchain_demo.node import Node
from blockchain_demo.types import block_hash, make_tx

FAST = {"timeout_propose": 0.3, "timeout_prevote": 0.15, "timeout_precommit": 0.15}


def make_network(tmp_path, n=4, byzantine=(), stake=100):
    keys = [KeyPair.generate() for _ in range(n)]
    acct = KeyPair.generate()
    genesis = {
        "chain_id": "test",
        "validators": {k.public_hex: stake for k in keys},
        "balances": {acct.public_hex: 10_000},
    }
    configs = []
    for i in range(n):
        cfg = {"node_id": i, "host": "127.0.0.1", "p2p_port": 0, "rpc_port": 0,
               "byzantine": i in byzantine, **FAST}
        configs.append(cfg)
        d = tmp_path / f"node{i}"
        d.mkdir()
        (d / "config.json").write_text(json.dumps(cfg))
        (d / "key.json").write_text(json.dumps(keys[i].to_dict()))
    nodes = [Node(tmp_path / f"node{i}", configs, genesis) for i in range(n)]
    return nodes, acct


class Hub:
    """Async message bus standing in for the TCP gossip network."""

    def __init__(self, nodes):
        self.nodes = nodes
        self.queue = asyncio.Queue()
        for node in nodes:
            node.broadcast = self._make_broadcast(node)
            node.log = lambda *a, **k: None

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
            await asyncio.sleep(0)  # yield so timers and other tasks can run


async def run_until(hub, nodes, height, timeout=20.0):
    async def _wait():
        while not all(n.height >= height for n in nodes):
            await asyncio.sleep(0.02)

    await asyncio.wait_for(_wait(), timeout)


def start(hub, nodes):
    for node in nodes:
        node.consensus.start_height(node.height)
    return asyncio.create_task(hub.run())


def assert_consistent(nodes, up_to=None):
    """All nodes must have finalized identical blocks at every height."""
    up_to = up_to or min(n.height for n in nodes)
    for h in range(up_to):
        hashes = {block_hash(n.blocks[h]) for n in nodes}
        assert len(hashes) == 1, f"conflicting finalized blocks at height {h}: {hashes}"


@pytest.fixture
def quiet():
    import builtins

    orig = builtins.print
    builtins.print = lambda *a, **k: None
    yield
    builtins.print = orig


def test_four_honest_nodes_finalize_same_chain(tmp_path, quiet):
    async def main():
        nodes, acct = make_network(tmp_path)
        hub = Hub(nodes)
        task = start(hub, nodes)
        # submit a transfer through node0
        tx = make_tx(acct, "bb" * 32, 50, 0)
        ok, reason = nodes[0].add_tx(tx)
        assert ok, reason
        await run_until(hub, nodes, 4)
        task.cancel()
        assert_consistent(nodes)
        assert all(n.chain_state.balances["bb" * 32] == 50 for n in nodes)

    asyncio.run(main())


def test_chain_progresses_with_one_validator_down(tmp_path, quiet):
    async def main():
        nodes, _ = make_network(tmp_path)
        live = nodes[:3]  # node3 never starts: f=1 < n/3
        hub = Hub(live)
        task = start(hub, live)
        await run_until(hub, live, 3)
        task.cancel()
        assert_consistent(live)

    asyncio.run(main())


def test_double_signer_is_detected_and_slashed(tmp_path, quiet):
    async def main():
        nodes, _ = make_network(tmp_path, byzantine=(3,))
        honest = nodes[:3]
        hub = Hub(nodes)
        task = start(hub, nodes)
        await run_until(hub, honest, 5)
        task.cancel()

        # Safety: honest nodes finalized one identical chain, no conflicts.
        assert_consistent(honest)

        # Accountability: node3's equivocation was proven and punished on-chain.
        bad_pub = nodes[3].pubkey
        for n in honest:
            assert n.chain_state.slashed, "no slash recorded"
            assert any(s["validator"] == bad_pub for s in n.chain_state.slashed)
            assert n.chain_state.validators[bad_pub] < 100
        # All honest nodes agree on the punishment (deterministic state).
        assert len({n.chain_state.validators[bad_pub] for n in honest}) == 1

    asyncio.run(main())


def test_soak_many_heights_with_byzantine_never_stalls(tmp_path, quiet):
    """Liveness soak: 1 of 4 validators double-signs every round; the chain
    must keep finalizing blocks for many heights and never fork."""

    async def main():
        nodes, _ = make_network(tmp_path, byzantine=(3,))
        honest = nodes[:3]
        hub = Hub(nodes)
        task = start(hub, nodes)
        try:
            await run_until(hub, honest, 60, timeout=60)
        finally:
            task.cancel()
        assert_consistent(honest)
        # the double-signer was slashed to zero and removed from the active set
        bad = nodes[3].pubkey
        for n in honest:
            assert n.chain_state.validators[bad] == 0
            assert bad not in n.chain_state.active_validators()

    asyncio.run(main())
