"""Node: wires consensus, state, mempool, evidence pool, persistence and RPC.

A node runs entirely on one asyncio loop. It talks to peers over localhost
TCP (gossip) and exposes a tiny JSON-lines RPC port for the CLI.
"""

from __future__ import annotations

import asyncio
import copy
import json
from pathlib import Path

from .consensus import Consensus
from .crypto import KeyPair
from .network import Network, Peer
from .state import ChainState, StateError
from .types import (
    block_body_matches_header,
    block_hash,
    evidence_culprit,
    evidence_key,
    validate_tx,
    validate_vote,
)


class Node:
    def __init__(self, node_dir: Path, all_configs: list[dict], genesis: dict):
        self.dir = node_dir
        self.config = json.loads((node_dir / "config.json").read_text())
        self.id: int = self.config["node_id"]
        self.byzantine: bool = bool(self.config.get("byzantine", False))
        self.key = KeyPair.from_dict(json.loads((node_dir / "key.json").read_text()))
        self.pubkey = self.key.public_hex

        self.chain_state = ChainState(genesis)
        self.genesis = genesis
        self.mempool: list[dict] = []
        self.evidence_pool: dict[tuple, dict] = {}
        self.blocks: list[dict] = []  # committed blocks, in order
        self.last_block_hash = "0" * 64
        self.height = 0  # next height to commit

        self._load_chain()

        peers = [
            {"host": c["host"], "port": c["p2p_port"]}
            for c in all_configs
            if c["node_id"] != self.id
        ]
        self.net = Network(
            self.config["host"],
            self.config["p2p_port"],
            peers,
            handler=self._on_net_message,
            peer_height=lambda: self.height,
            log=self.log,
        )
        self.consensus = Consensus(self)
        self._syncing = False

    # ------------------------------------------------------------------ logging
    def log(self, msg: str) -> None:
        tag = "BYZ" if self.byzantine else "node"
        print(f"[{tag}{self.id} h={self.height}] {msg}", flush=True)

    # -------------------------------------------------------------- persistence
    @property
    def _chain_file(self) -> Path:
        return self.dir / "chain.jsonl"

    def _load_chain(self) -> None:
        if not self._chain_file.exists():
            return
        for line in self._chain_file.read_text().splitlines():
            if not line.strip():
                continue
            record = json.loads(line)
            self.chain_state.apply_block(record["block"])
            self.blocks.append(record["block"])
            self.last_block_hash = block_hash(record["block"])
            self.height = record["block"]["header"]["height"] + 1
        if self.height:
            self.log(f"loaded {self.height} blocks from disk")

    def _persist(self, block: dict, commits: list[dict]) -> None:
        with self._chain_file.open("a") as f:
            f.write(json.dumps({"block": block, "commits": commits}) + "\n")

    # ------------------------------------------------------------- mempool/evidence
    def add_tx(self, tx: dict) -> tuple[bool, str]:
        if not validate_tx(tx):
            return False, "invalid signature or shape"
        if tx["nonce"] != self.chain_state.nonces.get(tx["sender"], 0):
            return False, "bad nonce"
        if self.chain_state.balances.get(tx["sender"], 0) < tx.get("amount", 0):
            return False, "insufficient funds"
        if not any(t["signature"] == tx["signature"] for t in self.mempool):
            self.mempool.append(tx)
            self.broadcast({"type": "tx", "data": tx})
        return True, "ok"

    def add_evidence(self, evidence: dict) -> bool:
        """Validate and pool equivocation evidence. Returns True if new."""
        key = evidence_key(evidence)
        if key is None or evidence_culprit(evidence) is None:
            return False
        if key in self.evidence_pool:
            return False
        self.evidence_pool[key] = evidence
        culprit = evidence_culprit(evidence)
        self.log(f"evidence pooled: double-sign by {culprit[:8]} at h={key[2]} r={key[3]}")
        return True

    def mempool_snapshot(self, limit: int) -> list[dict]:
        """Valid txs in nonce order, checked against a dry-run state."""
        state = self.chain_state
        picked: list[dict] = []
        for tx in list(self.mempool):
            if len(picked) >= limit:
                break
            try:
                state = copy.deepcopy(state)
                state.apply_tx(tx)
                picked.append(tx)
            except StateError:
                continue
        return picked

    def evidence_snapshot(self, limit: int) -> list[dict]:
        return list(self.evidence_pool.values())[:limit]

    # ------------------------------------------------------------------- commit
    def commit_block(self, block: dict, commits: list[dict]) -> None:
        header = block["header"]
        if header["height"] != self.height:
            return  # stale or already committed
        if header["prev_hash"] != self.last_block_hash:
            self.log(f"refusing block h={header['height']}: prev_hash mismatch")
            return
        # Defense in depth: never apply a block whose body does not match its
        # header, whose transactions/evidence do not execute cleanly, or whose
        # committed state root differs from the state we derive. An invalid tx
        # (bad signature / nonce / funds / contract fault) or a lying state root
        # makes the whole block invalid, so it can never be finalized on an
        # honest node — and such a block cannot have earned honest precommits
        # anyway (honest validators prevote nil for blocks that fail these checks).
        try:
            if not block_body_matches_header(block):
                raise StateError("block body does not match header roots")
            post = self.chain_state.dry_run_block(block)
            if post.state_root() != header["app_state_root"]:
                raise StateError("app_state_root mismatch")
        except StateError as exc:
            self.log(f"refusing block h={header['height']}: {exc}")
            return
        self.chain_state = post
        included = {t["signature"] for t in block["txs"]}
        self.mempool = [t for t in self.mempool if t["signature"] not in included]
        for ev in block["evidence"]:
            self.evidence_pool.pop(evidence_key(ev), None)
        self.blocks.append(block)
        self.last_block_hash = block_hash(block)
        self.height = header["height"] + 1
        self._persist(block, commits)
        self.log(
            f"COMMIT h={header['height']} block={self.last_block_hash[:8]} "
            f"state={header['app_state_root'][:8]} "
            f"txs={len(block['txs'])} evidence={len(block['evidence'])}"
        )
        for tx in block["txs"]:
            self._log_tx(tx)
        for ev in block["evidence"]:
            culprit = evidence_culprit(ev)
            stake = self.chain_state.validators.get(culprit, 0)
            self.log(f"SLASHED {culprit[:8]} for double-signing; stake now {stake}")
        self.consensus.start_height(self.height)

    def _log_tx(self, tx: dict) -> None:
        kind = tx.get("kind", "transfer")
        if kind == "deploy":
            from .contract import contract_address

            addr = contract_address(tx["sender"], tx["nonce"])
            self.log(f"  deploy   {tx['sender'][:8]} -> contract {addr[:8]} ({len(tx['code'])//2} bytes)")
        elif kind == "call":
            self.log(
                f"  call     {tx['sender'][:8]} -> {tx['contract'][:8]} "
                f"calldata={tx.get('calldata', 0)} amount={tx.get('amount', 0)}"
            )
        else:
            self.log(
                f"  transfer {tx['sender'][:8]} -> {tx['recipient'][:8]} "
                f"amount={tx['amount']} (nonce {tx['nonce']})"
            )

    # --------------------------------------------------------------------- sync
    def maybe_sync(self) -> None:
        """Ask peers for blocks when we learn we're behind."""
        if not self._syncing:
            self._syncing = True
            self.broadcast({"type": "sync_request", "data": {"from_height": self.height}})

    def request_block(self, height: int, target_hash: str) -> None:
        self.broadcast({"type": "block_request", "data": {"height": height, "hash": target_hash}})

    def _handle_sync_request(self, data: dict, peer: Peer) -> None:
        start = max(0, int(data.get("from_height", 0)))
        records = []
        for line in self._read_chain_records(start, limit=200):
            records.append(line)
        if records:
            peer.send({"type": "sync_response", "data": {"records": records}})

    def _read_chain_records(self, start: int, limit: int) -> list[dict]:
        if not self._chain_file.exists():
            return []
        out = []
        for line in self._chain_file.read_text().splitlines():
            if not line.strip():
                continue
            rec = json.loads(line)
            if rec["block"]["header"]["height"] >= start:
                out.append(rec)
                if len(out) >= limit:
                    break
        return out

    def _handle_sync_response(self, data: dict) -> None:
        for rec in data.get("records", []):
            block, commits = rec["block"], rec["commits"]
            if block["header"]["height"] != self.height:
                continue
            if block["header"]["prev_hash"] != self.last_block_hash:
                continue
            if not self._verify_commits(block, commits):
                self.log("sync: rejected block with invalid commit proof")
                continue
            self.commit_block(block, commits)
        self._syncing = False

    def _verify_commits(self, block: dict, commits: list[dict]) -> bool:
        """Finality check: >2/3 of current stake precommitted this exact block."""
        target = block_hash(block)
        stake = 0
        seen = set()
        for vote in commits:
            if not validate_vote(vote):
                return False
            if vote["type"] != "precommit" or vote["height"] != block["header"]["height"]:
                return False
            if vote["block_hash"] != target or vote["validator"] in seen:
                return False
            seen.add(vote["validator"])
            stake += self.chain_state.validators.get(vote["validator"], 0)
        return stake > self.chain_state.total_stake * 2 / 3

    def _handle_block_request(self, data: dict, peer: Peer) -> None:
        for rec in self._read_chain_records(int(data.get("height", 0)), limit=1):
            if block_hash(rec["block"]) == data.get("hash"):
                peer.send({"type": "sync_response", "data": {"records": [rec]}})

    # ------------------------------------------------------------------ network
    def broadcast(self, msg: dict) -> None:
        self.net.broadcast(msg)

    def _on_net_message(self, msg: dict, peer: Peer) -> None:
        mtype, data = msg.get("type"), msg.get("data", {})
        if mtype == "hello":
            peer.height = data.get("height", 0)
            if peer.height > self.height:
                self.maybe_sync()
        elif mtype == "proposal":
            self.consensus.on_proposal(data)
        elif mtype == "vote":
            self.consensus.on_vote(data)
        elif mtype == "evidence":
            self.consensus.on_evidence(data)
        elif mtype == "tx":
            self.add_tx(data)
        elif mtype == "sync_request":
            if peer is not None:
                self._handle_sync_request(data, peer)
        elif mtype == "sync_response":
            self._handle_sync_response(data)
        elif mtype == "block_request":
            if peer is not None:
                self._handle_block_request(data, peer)

    # ---------------------------------------------------------------------- RPC
    async def _handle_rpc(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            line = await reader.readline()
            req = json.loads(line)
            resp = self._rpc_dispatch(req)
        except Exception as exc:  # noqa: BLE001 - RPC must never crash the node
            resp = {"ok": False, "error": str(exc)}
        writer.write(json.dumps(resp).encode() + b"\n")
        await writer.drain()
        writer.close()

    def _rpc_dispatch(self, req: dict) -> dict:
        cmd = req.get("cmd")
        if cmd == "submit_tx":
            ok, reason = self.add_tx(req["tx"])
            return {"ok": ok, "reason": reason}
        if cmd == "status":
            return {
                "ok": True,
                "node_id": self.id,
                "byzantine": self.byzantine,
                "height": self.height,
                "last_block_hash": self.last_block_hash,
                "validators": dict(self.chain_state.validators),
                "slashed": self.chain_state.slashed,
                "mempool": len(self.mempool),
            }
        if cmd == "balances":
            return {"ok": True, "balances": dict(self.chain_state.balances)}
        if cmd == "accounts":
            # Full account view: address -> {balance, nonce, code (contracts),
            # storage_root}. Unknown addresses default to balance/nonce 0.
            st = self.chain_state
            addrs = set(st.balances) | set(st.nonces) | set(st.codes)
            return {
                "ok": True,
                "accounts": {
                    a: {
                        "balance": st.balances.get(a, 0),
                        "nonce": st.nonces.get(a, 0),
                        "code": st.codes.get(a, ""),
                        "storage_root": st.storage_root(a),
                    }
                    for a in sorted(addrs)
                },
            }
        if cmd == "nonce":
            return {"ok": True, "nonce": self.chain_state.nonces.get(req.get("address"), 0)}
        if cmd == "block":
            h = int(req.get("height", self.height - 1))
            for rec in self._read_chain_records(h, limit=1_000_000):
                if rec["block"]["header"]["height"] == h:
                    return {"ok": True, "record": rec}
            return {"ok": False, "error": "not found"}
        if cmd in ("prove_account", "prove_storage"):
            return self._rpc_prove(cmd, req)
        return {"ok": False, "error": f"unknown command {cmd!r}"}

    def _rpc_prove(self, cmd: str, req: dict) -> dict:
        """Serve a state proof bound to the latest finalized block.

        Returns the block header (which commits `app_state_root`), the >2/3
        precommit votes that finalize it, and the Merkle proof. A light client
        verifies finality from the votes, takes `app_state_root` from the
        header, and checks the proof against it — it never trusts this node for
        the account/storage value itself.
        """
        latest = None
        for rec in self._read_chain_records(0, limit=1_000_000):
            latest = rec
        if latest is None:
            return {"ok": False, "error": "no finalized block yet"}
        st = self.chain_state
        if cmd == "prove_account":
            proof = st.account_proof(req.get("address", ""))
        else:
            proof = st.storage_proof(req.get("address", ""), req.get("slot", "0"))
        return {
            "ok": True,
            "header": latest["block"]["header"],
            "block_hash": block_hash(latest["block"]),
            "commits": latest["commits"],
            "proof": proof,
        }

    # ---------------------------------------------------------------------- run
    async def run(self) -> None:
        await self.net.start()
        rpc = await asyncio.start_server(
            self._handle_rpc, self.config["host"], self.config["rpc_port"]
        )
        self.log(
            f"started (p2p :{self.config['p2p_port']}, rpc :{self.config['rpc_port']}"
            f"{', BYZANTINE' if self.byzantine else ''})"
        )
        self.consensus.start_height(self.height)
        async with rpc:
            await asyncio.Event().wait()  # run forever
