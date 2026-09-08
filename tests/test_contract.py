"""Contract accounts, the contract VM, and state-commitment tests.

Covers: contract deployment creates a contract account at a deterministic
address; contract calls write storage; the state root changes with every state
change and is identical across independently-derived states; deploy/call txs
are ECDSA-signed and validated; faults (bad opcode, call to non-contract) are
rejected and roll back atomically.
"""

import pytest

from blockchain_demo.contract import (
    ContractError,
    OP_ADD,
    OP_PUSH1,
    OP_SLOAD,
    OP_SSTORE,
    OP_STOP,
    contract_address,
    run_code,
    word_hex,
)
from blockchain_demo.crypto import AccountKey, KeyPair
from blockchain_demo.state import ChainState, StateError
from blockchain_demo.types import (
    CHAIN_ID,
    make_block,
    make_call_tx,
    make_deploy_tx,
    make_tx,
    validate_tx,
)


def _genesis(n_accounts=2, balance=10_000):
    vals = [KeyPair.generate() for _ in range(4)]
    accts = [AccountKey.generate() for _ in range(n_accounts)]
    genesis = {
        "chain_id": CHAIN_ID,
        "validators": {k.public_hex: 100 for k in vals},
        "balances": {a.address: balance for a in accts},
    }
    return genesis, accts


# Counter-style contract: store calldata at slot 0.
# Stack starts with [calldata]. PUSH1 0 -> [calldata, 0]; SSTORE pops key=0
# then value=calldata, so storage[0] = calldata.
COUNTER_CODE = bytes([OP_PUSH1, 0x00, OP_SSTORE, OP_STOP]).hex()


# ----------------------------------------------------------------------- VM
def test_run_code_stores_calldata():
    storage = {}
    run_code(COUNTER_CODE, storage, calldata=42)
    assert storage[word_hex(0)] == word_hex(42)


def test_run_code_sload_and_add():
    # Read slot 0, add 1, store back at slot 0.
    # PUSH1 0 SLOAD PUSH1 1 ADD PUSH1 0 SSTORE STOP
    code = bytes(
        [OP_PUSH1, 0x00, OP_SLOAD, OP_PUSH1, 0x01, OP_ADD, OP_PUSH1, 0x00, OP_SSTORE, OP_STOP]
    ).hex()
    storage = {word_hex(0): word_hex(41)}
    run_code(code, storage, calldata=0)
    assert storage[word_hex(0)] == word_hex(42)


def test_invalid_opcode_faults():
    with pytest.raises(ContractError):
        run_code(bytes([0xEE]).hex(), {}, 0)


def test_stack_underflow_faults():
    # SSTORE on an empty-ish stack (only calldata present; needs two words).
    with pytest.raises(ContractError):
        run_code(bytes([OP_SSTORE, OP_STOP]).hex(), {}, 0)


def test_contract_address_is_deterministic():
    a = AccountKey.generate().address
    assert contract_address(a, 0) == contract_address(a, 0)
    assert contract_address(a, 0) != contract_address(a, 1)
    assert len(contract_address(a, 0)) == 40  # same address shape as an EOA


# ------------------------------------------------------------- state/contract
def test_deploy_creates_contract_account():
    genesis, accts = _genesis()
    st = ChainState(genesis)
    st.apply_tx(make_deploy_tx(accts[0], COUNTER_CODE, 0))
    addr = contract_address(accts[0].address, 0)
    assert st.codes[addr] == COUNTER_CODE
    assert addr in st.storages
    assert st.nonces[accts[0].address] == 1


def test_call_writes_contract_storage():
    genesis, accts = _genesis()
    st = ChainState(genesis)
    st.apply_tx(make_deploy_tx(accts[0], COUNTER_CODE, 0))
    addr = contract_address(accts[0].address, 0)
    st.apply_tx(make_call_tx(accts[0], addr, 1, calldata=7))
    assert st.storages[addr][word_hex(0)] == word_hex(7)
    # a second call overwrites the slot
    st.apply_tx(make_call_tx(accts[0], addr, 2, calldata=99))
    assert st.storages[addr][word_hex(0)] == word_hex(99)


def test_call_to_non_contract_rejected():
    genesis, accts = _genesis()
    st = ChainState(genesis)
    with pytest.raises(StateError):
        st.apply_tx(make_call_tx(accts[0], "ab" * 20, 0, calldata=1))


def test_contract_call_with_value_moves_funds():
    genesis, accts = _genesis()
    st = ChainState(genesis)
    st.apply_tx(make_deploy_tx(accts[0], COUNTER_CODE, 0))
    addr = contract_address(accts[0].address, 0)
    st.apply_tx(make_call_tx(accts[0], addr, 1, calldata=1, amount=500))
    assert st.balances[addr] == 500
    assert st.balances[accts[0].address] == 10_000 - 500


def test_faulting_call_rolls_back_storage_and_funds():
    # A call whose code faults must write nothing and move nothing.
    bad_code = bytes([0xEE]).hex()  # invalid opcode
    genesis, accts = _genesis()
    st = ChainState(genesis)
    st.apply_tx(make_deploy_tx(accts[0], bad_code, 0))
    addr = contract_address(accts[0].address, 0)
    before_root = st.state_root()
    with pytest.raises(StateError):
        st.apply_tx(make_call_tx(accts[0], addr, 1, calldata=1, amount=100))
    assert st.storages[addr] == {}
    assert st.balances.get(addr, 0) == 0
    assert st.state_root() == before_root  # nothing changed


def test_deploy_and_call_txs_are_signed_and_validated():
    acct = AccountKey.generate()
    d = make_deploy_tx(acct, COUNTER_CODE, 0)
    assert validate_tx(d)
    d["code"] = "ffff"  # tamper after signing
    assert not validate_tx(d)
    c = make_call_tx(acct, "ab" * 20, 0, calldata=5, amount=1)
    assert validate_tx(c)
    c["calldata"] = 6
    assert not validate_tx(c)


def test_state_root_changes_with_every_transition_and_agrees_across_nodes():
    genesis, accts = _genesis()
    st1 = ChainState(genesis)
    st2 = ChainState(genesis)  # independent node, same genesis
    assert st1.state_root() == st2.state_root()

    block = make_block(
        1, 0, "0" * 64, 1.0, "x",
        [make_tx(accts[0], accts[1].address, 100, 0)], [],
    )
    post1 = st1.dry_run_block(block)
    post2 = st2.dry_run_block(block)
    # independent derivation yields the identical post-block state root
    assert post1.state_root() == post2.state_root()
    assert post1.state_root() != st1.state_root()


def test_state_root_includes_contract_storage():
    genesis, accts = _genesis()
    st = ChainState(genesis)
    st.apply_tx(make_deploy_tx(accts[0], COUNTER_CODE, 0))
    addr = contract_address(accts[0].address, 0)
    after_deploy = st.state_root()
    st.apply_tx(make_call_tx(accts[0], addr, 1, calldata=7))
    after_call = st.state_root()
    assert after_call != after_deploy  # a storage write changes the commitment
    # and the account leaf's storage_root matches the contract's storage trie
    assert st.storage_root(addr) in st.account_leaf_value(addr)
