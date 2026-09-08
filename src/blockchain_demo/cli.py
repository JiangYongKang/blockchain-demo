"""Command line interface.

  blockchain-demo init [--nodes N] [--byzantine I]   generate keys/genesis/configs
  blockchain-demo run --node I                        run one validator process
  blockchain-demo start-all [--nodes N]               spawn N validator processes
  blockchain-demo tx --from A --to B --amount X     submit a transfer
  blockchain-demo status                              query all nodes
"""

from __future__ import annotations

import argparse
import asyncio
import json
import shutil
import signal
import subprocess
import sys
from pathlib import Path

from .crypto import KeyPair
from .node import Node
from .state import GENESIS_BALANCE, GENESIS_STAKE
from .types import CHAIN_ID, make_tx

BASE_DIR = Path(".chain-data")
P2P_BASE = 26660
RPC_BASE = 27660
NUM_ACCOUNTS = 5


# --------------------------------------------------------------------- helpers
def load_configs(base: Path) -> list[dict]:
    cfg_path = base / "configs.json"
    if not cfg_path.exists():
        sys.exit(f"no network found at {base}/ — run `blockchain-demo init` first")
    return json.loads(cfg_path.read_text())


def load_genesis(base: Path) -> dict:
    return json.loads((base / "genesis.json").read_text())


async def rpc_call(port: int, req: dict) -> dict:
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    writer.write(json.dumps(req).encode() + b"\n")
    await writer.drain()
    line = await reader.readline()
    writer.close()
    return json.loads(line)


# --------------------------------------------------------------------- commands
def cmd_init(args: argparse.Namespace) -> None:
    base = Path(args.dir)
    if base.exists():
        if not args.force:
            sys.exit(f"{base} already exists (use --force to reinitialize)")
        shutil.rmtree(base)
    base.mkdir(parents=True)

    validator_keys = [KeyPair.generate() for _ in range(args.nodes)]
    account_keys = [KeyPair.generate() for _ in range(NUM_ACCOUNTS)]

    genesis = {
        "chain_id": CHAIN_ID,
        "validators": {k.public_hex: GENESIS_STAKE for k in validator_keys},
        "balances": {k.public_hex: GENESIS_BALANCE for k in account_keys},
    }
    (base / "genesis.json").write_text(json.dumps(genesis, indent=2))

    configs = []
    for i, key in enumerate(validator_keys):
        cfg = {
            "node_id": i,
            "host": "127.0.0.1",
            "p2p_port": P2P_BASE + i,
            "rpc_port": RPC_BASE + i,
            "byzantine": i == args.byzantine,
            "timeout_propose": 2.0,
            "timeout_prevote": 1.0,
            "timeout_precommit": 1.0,
        }
        configs.append(cfg)
        node_dir = base / f"node{i}"
        node_dir.mkdir()
        (node_dir / "config.json").write_text(json.dumps(cfg, indent=2))
        (node_dir / "key.json").write_text(json.dumps(key.to_dict()))

    (base / "configs.json").write_text(json.dumps(configs, indent=2))
    accounts_dir = base / "accounts"
    accounts_dir.mkdir()
    for j, key in enumerate(account_keys):
        (accounts_dir / f"acc{j}.json").write_text(json.dumps(key.to_dict()))

    print(f"initialized {args.nodes} validators in {base}/")
    if args.byzantine is not None:
        print(f"node{args.byzantine} is configured BYZANTINE (will double-sign)")
    for j, key in enumerate(account_keys):
        print(f"  account acc{j}: {key.public_hex[:16]}… balance={GENESIS_BALANCE}")


def cmd_run(args: argparse.Namespace) -> None:
    base = Path(args.dir)
    configs = load_configs(base)
    genesis = load_genesis(base)
    node = Node(base / f"node{args.node}", configs, genesis)
    asyncio.run(node.run())


def cmd_start_all(args: argparse.Namespace) -> None:
    base = Path(args.dir)
    configs = load_configs(base)
    procs: list[subprocess.Popen] = []
    for cfg in configs:
        procs.append(
            subprocess.Popen(
                [sys.executable, "-m", "blockchain_demo", "--dir", str(base),
                 "run", "--node", str(cfg["node_id"])],
            )
        )
    print(f"started {len(procs)} validator processes; Ctrl-C to stop")

    def shutdown(*_):
        for p in procs:
            p.terminate()

    signal.signal(signal.SIGINT, shutdown)
    signal.signal(signal.SIGTERM, shutdown)
    for p in procs:
        p.wait()


def cmd_stop_all(args: argparse.Namespace) -> None:
    import subprocess as sp

    sp.run(["pkill", "-f", "blockchain_demo.*run"], check=False)
    print("stopped all validator processes")


def cmd_tx(args: argparse.Namespace) -> None:
    base = Path(args.dir)
    configs = load_configs(base)
    sender = KeyPair.from_dict(json.loads((base / "accounts" / f"acc{args.sender}.json").read_text()))
    recipient = KeyPair.from_dict(
        json.loads((base / "accounts" / f"acc{args.recipient}.json").read_text())
    )
    nonce_resp = asyncio.run(
        rpc_call(configs[args.node]["rpc_port"], {"cmd": "nonce", "address": sender.public_hex})
    )
    nonce = nonce_resp.get("nonce", 0)
    tx = make_tx(sender, recipient.public_hex, args.amount, nonce)
    result = asyncio.run(rpc_call(configs[args.node]["rpc_port"], {"cmd": "submit_tx", "tx": tx}))
    print(json.dumps(result))


def cmd_status(args: argparse.Namespace) -> None:
    base = Path(args.dir)
    configs = load_configs(base)
    for cfg in configs:
        try:
            resp = asyncio.run(rpc_call(cfg["rpc_port"], {"cmd": "status"}))
        except OSError:
            print(f"node{cfg['node_id']}: unreachable")
            continue
        validators = {k[:8]: v for k, v in resp["validators"].items()}
        print(
            f"node{resp['node_id']}{' [BYZANTINE]' if resp['byzantine'] else ''}: "
            f"height={resp['height']} tip={resp['last_block_hash'][:12]} "
            f"mempool={resp['mempool']}"
        )
        print(f"   validators={validators}")
        for s in resp["slashed"]:
            print(
                f"   SLASHED {s['validator'][:8]} kind={s['kind']} "
                f"at h={s['height']} r={s['round']} penalty={s['penalty']} remaining={s['remaining']}"
            )


# ------------------------------------------------------------------------- main
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="blockchain-demo")
    p.add_argument("--dir", default=str(BASE_DIR), help="chain data directory")
    sub = p.add_subparsers(dest="command", required=True)

    sp = sub.add_parser("init", help="generate keys, genesis and node configs")
    sp.add_argument("--nodes", type=int, default=4)
    sp.add_argument("--byzantine", type=int, default=None, help="index of a node that will double-sign")
    sp.add_argument("--force", action="store_true")
    sp.set_defaults(fn=cmd_init)

    sp = sub.add_parser("run", help="run one validator node")
    sp.add_argument("--node", type=int, required=True)
    sp.set_defaults(fn=cmd_run)

    sp = sub.add_parser("start-all", help="spawn all validator processes")
    sp.set_defaults(fn=cmd_start_all)

    sp = sub.add_parser("stop", help="stop all validator processes")
    sp.set_defaults(fn=cmd_stop_all)

    sp = sub.add_parser("tx", help="submit a transfer between demo accounts")
    sp.add_argument("--from", dest="sender", type=int, required=True)
    sp.add_argument("--to", dest="recipient", type=int, required=True)
    sp.add_argument("--amount", type=int, required=True)
    sp.add_argument("--node", type=int, default=0, help="node to submit through")
    sp.set_defaults(fn=cmd_tx)

    sp = sub.add_parser("status", help="print height/validators/slashing for all nodes")
    sp.set_defaults(fn=cmd_status)
    return p


def main() -> None:
    args = build_parser().parse_args()
    args.fn(args)
