"""End-to-end test over real localhost TCP: 4 validator nodes (1 Byzantine)
gossiping on ephemeral ports, finalizing blocks, transferring account funds
(ECDSA) and slashing the equivocator.
"""

import asyncio
import json
import socket

from blockchain_demo.crypto import AccountKey, KeyPair
from blockchain_demo.node import Node
from blockchain_demo.types import CHAIN_ID, block_hash, make_tx

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
        sender = AccountKey.generate()
        recipient = AccountKey.generate()
        genesis = {
            "chain_id": CHAIN_ID,
            "validators": {k.public_hex: 100 for k in keys},
            "balances": {sender.address: 5_000, recipient.address: 1_000},
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
            # submit a valid transfer and an invalid one through node0
            ok, reason = nodes[0].add_tx(make_tx(sender, recipient.address, 700, 0))
            assert ok, reason
            ok, _ = nodes[0].add_tx(make_tx(sender, recipient.address, 999_999_999, 0))
            assert not ok  # insufficient funds

            async def _wait():
                # Wait until the transfer is *finalized on every honest node*
                # (balance + nonce updated) and the chain has advanced. Over
                # real TCP the tx must gossip before a proposer includes it,
                # so we wait on the condition rather than a fixed height.
                while True:
                    applied = all(
                        nd.chain_state.balances[sender.address] == 4_300
                        and nd.chain_state.nonces[sender.address] == 1
                        for nd in nodes[:3]
                    )
                    slashed = all(
                        any(s["validator"] == nodes[3].pubkey for s in nd.chain_state.slashed)
                        for nd in nodes[:3]
                    )
                    if applied and slashed and all(nd.height >= 4 for nd in nodes[:3]):
                        return
                    await asyncio.sleep(0.05)

            await asyncio.wait_for(_wait(), timeout=30)

            # one finalized chain, no conflicts at every shared height
            common = min(len(nd.blocks) for nd in nodes[:3])
            for h in range(common):
                hashes = {block_hash(nd.blocks[h]) for nd in nodes[:3]}
                assert len(hashes) == 1

            # account state identical on every honest node, transfer applied
            for nd in nodes[:3]:
                assert nd.chain_state.balances[sender.address] == 4_300
                assert nd.chain_state.balances[recipient.address] == 1_700
                assert nd.chain_state.nonces[sender.address] == 1

            # the Byzantine double-signer was slashed on all honest nodes
            bad = nodes[3].pubkey
            for nd in nodes[:3]:
                assert any(s["validator"] == bad for s in nd.chain_state.slashed)
                assert nd.chain_state.validators[bad] < 100
        finally:
            for node in nodes:
                await node.net.stop()

    asyncio.run(main())
