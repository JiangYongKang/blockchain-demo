"""Command line interface.

  blockchain-demo init [--nodes N] [--byzantine I]   generate keys/genesis/configs
  blockchain-demo run --node I                        run one validator process
  blockchain-demo start-all [--nodes N]               spawn N validator processes
  blockchain-demo tx --from A --to B --amount X     submit a transfer
  blockchain-demo status                              query all nodes
  blockchain-demo balances                            query account balances/nonces
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

from .crypto import AccountKey, KeyPair
from .contract import contract_address, word_hex
from . import light
from .node import Node
from .state import GENESIS_BALANCE, GENESIS_STAKE
from .types import CHAIN_ID, make_call_tx, make_deploy_tx, make_tx

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
    account_keys = [AccountKey.generate() for _ in range(NUM_ACCOUNTS)]

    genesis = {
        "chain_id": CHAIN_ID,
        "validators": {k.public_hex: GENESIS_STAKE for k in validator_keys},
        "balances": {k.address: GENESIS_BALANCE for k in account_keys},
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
        print(f"  account acc{j}: {key.address} balance={GENESIS_BALANCE}")


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


def _load_account(base: Path, idx: int) -> AccountKey:
    return AccountKey.from_dict(
        json.loads((base / "accounts" / f"acc{idx}.json").read_text())
    )


def _resolve_address(base: Path, ref: str) -> str:
    """Resolve `accN` to that account's address; pass a hex address through."""
    if ref.startswith("acc") and ref[3:].isdigit():
        return _load_account(base, int(ref[3:])).address
    return ref


def _get_nonce(configs: dict, node: int, address: str) -> int:
    resp = asyncio.run(
        rpc_call(configs[node]["rpc_port"], {"cmd": "nonce", "address": address})
    )
    return resp.get("nonce", 0)


def cmd_tx(args: argparse.Namespace) -> None:
    base = Path(args.dir)
    configs = load_configs(base)
    sender = _load_account(base, args.sender)
    recipient = _load_account(base, args.recipient)
    nonce = _get_nonce(configs, args.node, sender.address)
    tx = make_tx(sender, recipient.address, args.amount, nonce)
    result = asyncio.run(
        rpc_call(configs[args.node]["rpc_port"], {"cmd": "submit_tx", "tx": tx})
    )
    print(json.dumps(result))


def cmd_deploy(args: argparse.Namespace) -> None:
    """Deploy a contract. Prints the derived contract address (deterministic)."""
    base = Path(args.dir)
    configs = load_configs(base)
    sender = _load_account(base, args.sender)
    nonce = _get_nonce(configs, args.node, sender.address)
    addr = contract_address(sender.address, nonce)
    tx = make_deploy_tx(sender, args.code, nonce)
    result = asyncio.run(
        rpc_call(configs[args.node]["rpc_port"], {"cmd": "submit_tx", "tx": tx})
    )
    print(json.dumps({**result, "contract": addr}))


def cmd_call(args: argparse.Namespace) -> None:
    """Invoke a contract: `--to` is a hex contract address or `accN`."""
    base = Path(args.dir)
    configs = load_configs(base)
    sender = _load_account(base, args.sender)
    contract = _resolve_address(base, args.to)
    nonce = _get_nonce(configs, args.node, sender.address)
    tx = make_call_tx(sender, contract, nonce, calldata=args.calldata, amount=args.amount)
    result = asyncio.run(
        rpc_call(configs[args.node]["rpc_port"], {"cmd": "submit_tx", "tx": tx})
    )
    print(json.dumps(result))


def cmd_proof(args: argparse.Namespace) -> None:
    """Fetch a state proof and verify it as a light client, locally.

    Trusts only the genesis validator set (public keys in genesis.json) and the
    block header + precommit votes + Merkle proof returned by the node — never
    the node's stated value. Prints VERIFIED with the proven value, or REJECTED.
    """
    base = Path(args.dir)
    configs = load_configs(base)
    port = configs[args.node]["rpc_port"]
    genesis = load_genesis(base)
    validators = dict(genesis["validators"])  # the light client's trusted set

    address = _resolve_address(base, args.address)
    if args.what == "balance":
        resp = asyncio.run(rpc_call(port, {"cmd": "prove_account", "address": address}))
        if not resp.get("ok"):
            print(f"REJECTED: {resp.get('error')}")
            return
        result = light.verify_account(
            resp["header"], resp["commits"], validators, address, resp["proof"]
        )
        if result is None:
            print("REJECTED: finality or account proof failed verification")
            return
        print(
            f"VERIFIED final block h={resp['header']['height']} "
            f"state={resp['header']['app_state_root'][:16]}…"
        )
        if result["exists"]:
            kind = "contract" if result["code"] else "account"
            print(
                f"  {kind} {address[:16]}… balance={result['balance']} "
                f"nonce={result['nonce']} storage_root={result['storage_root'][:16]}…"
            )
        else:
            print(f"  account {address[:16]}… does NOT exist in this state (proven absence)")
    else:  # storage slot
        slot = word_hex(int(args.slot, 0))
        resp = asyncio.run(
            rpc_call(port, {"cmd": "prove_storage", "address": address, "slot": slot})
        )
        if not resp.get("ok"):
            print(f"REJECTED: {resp.get('error')}")
            return
        result = light.verify_storage(
            resp["header"], resp["commits"], validators, address, slot, resp["proof"]
        )
        if result is None:
            print("REJECTED: finality or storage proof failed verification")
            return
        print(
            f"VERIFIED final block h={resp['header']['height']} "
            f"state={resp['header']['app_state_root'][:16]}…"
        )
        print(
            f"  contract {address[:16]}… slot 0x{int(slot,16):x} = "
            f"0x{int(result['value'],16):x} ({int(result['value'],16)})"
        )


def cmd_balances(args: argparse.Namespace) -> None:
    """Show every account's balance and nonce as seen by each node.

    Honest nodes must report identical values once the transfers are
    finalized.
    """
    base = Path(args.dir)
    configs = load_configs(base)
    accounts = {}
    acc_dir = base / "accounts"
    if acc_dir.exists():
        for p in sorted(acc_dir.glob("acc*.json")):
            key = AccountKey.from_dict(json.loads(p.read_text()))
            accounts[p.stem] = key.address
    addr_to_name = {addr: name for name, addr in accounts.items()}
    for cfg in configs:
        try:
            resp = asyncio.run(rpc_call(cfg["rpc_port"], {"cmd": "accounts"}))
        except OSError:
            print(f"node{cfg['node_id']}: unreachable")
            continue
        if not resp.get("ok"):
            print(f"node{cfg['node_id']}: {resp.get('error', 'error')}")
            continue
        accts = resp.get("accounts", {})
        print(f"node{cfg['node_id']}:")
        for addr in sorted(accts, key=lambda a: addr_to_name.get(a, f"zzz{a}")):
            label = addr_to_name.get(addr, "?     ")
            info = accts[addr]
            print(
                f"   {label} {addr[:12]}… balance={info['balance']:>10} "
                f"nonce={info['nonce']}"
            )


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

    sp = sub.add_parser("deploy", help="deploy contract bytecode from a demo account")
    sp.add_argument("--from", dest="sender", type=int, required=True)
    sp.add_argument("--code", type=str, required=True, help="hex bytecode, e.g. 0060ff")
    sp.add_argument("--node", type=int, default=0)
    sp.set_defaults(fn=cmd_deploy)

    sp = sub.add_parser("call", help="invoke a contract (calldata word, optional value)")
    sp.add_argument("--from", dest="sender", type=int, required=True)
    sp.add_argument("--to", dest="to", type=str, required=True, help="contract hex address")
    sp.add_argument("--calldata", type=lambda s: int(s, 0), default=0)
    sp.add_argument("--amount", type=int, default=0)
    sp.add_argument("--node", type=int, default=0)
    sp.set_defaults(fn=cmd_call)

    sp = sub.add_parser(
        "proof",
        help="fetch a light-client proof for an account balance or storage slot and verify it",
    )
    sp.add_argument("what", choices=("balance", "storage"))
    sp.add_argument("--address", type=str, required=True, help="hex address or accN")
    sp.add_argument("--slot", type=str, default="0", help="storage slot (hex or decimal)")
    sp.add_argument("--node", type=int, default=0)
    sp.set_defaults(fn=cmd_proof)

    sp = sub.add_parser("status", help="print height/validators/slashing for all nodes")
    sp.set_defaults(fn=cmd_status)

    sp = sub.add_parser("balances", help="print account balances and nonces on all nodes")
    sp.set_defaults(fn=cmd_balances)
    return p


def main() -> None:
    args = build_parser().parse_args()
    args.fn(args)
