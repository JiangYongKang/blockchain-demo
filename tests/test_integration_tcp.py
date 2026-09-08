"""End-to-end test over real localhost TCP: 4 validator nodes (1 Byzantine)
gossiping on ephemeral ports, finalizing blocks and slashing the equivocator.
"""

import asyncio
import json
import socket

from blockchain_demo.crypto import KeyPair
from blockchain_demo.node import Node
from blockchain_demo.types import block_hash

FAST = {"timeout_propose": 0.4, "timeout_prevote": 0.2, "timeout_precommit": 0.2}


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def test_four_nodes_over_tcp_with_byzantine(tmp_path):
    async def main():
        n = 4
        keys = [KeyPair.generate() for _ in range(n)]
        genesis = {
            "chain_id": "test",
            "validators": {k.public_hex: 100 for k in keys},
            "balances": {},
        }
        configs = []
        for i in range(n):
            cfg = {
                "node_id": i,
                "host": "127.0.0.1",
                "p2p_port": free_port(),
                "rpc_port": free_port(),
                "byzantine": i == 3,
                **FAST,
            }
            configs.append(cfg)
            d = tmp_path / f"node{i}"
            d.mkdir()
            (d / "config.json").write_text(json.dumps(cfg))
            (d / "key.json").write_text(json.dumps(keys[i].to_dict()))

        nodes = [Node(tmp_path / f"node{i}", configs, genesis) for i in range(n)]
        for node in nodes:
            node.log = lambda *a, **k: None
            await node.net.start()
            node.consensus.start_height(0)

        try:
            async def _wait():
                while not all(nd.height >= 4 for nd in nodes[:3]):
                    await asyncio.sleep(0.05)

            await asyncio.wait_for(_wait(), timeout=30)

            # one finalized chain, no conflicts
            for h in range(4):
                hashes = {block_hash(nd.blocks[h]) for nd in nodes[:3]}
                assert len(hashes) == 1

            # the Byzantine double-signer was slashed on all honest nodes
            bad = nodes[3].pubkey
            for nd in nodes[:3]:
                assert any(s["validator"] == bad for s in nd.chain_state.slashed)
                assert nd.chain_state.validators[bad] < 100
        finally:
            for node in nodes:
                await node.net.stop()

    asyncio.run(main())
