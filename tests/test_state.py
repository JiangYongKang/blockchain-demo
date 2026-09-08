import pytest

from blockchain_demo.crypto import AccountKey, KeyPair
from blockchain_demo.state import ChainState, StateError
from blockchain_demo.types import (
    CHAIN_ID,
    PRECOMMIT,
    make_block,
    make_evidence,
    make_tx,
    make_vote,
)


def _genesis(n_validators=4, stake=100, balance=1000, n_accounts=3, chain_id=CHAIN_ID):
    vals = [KeyPair.generate() for _ in range(n_validators)]
    accts = [AccountKey.generate() for _ in range(n_accounts)]
    genesis = {
        "chain_id": chain_id,
        "validators": {k.public_hex: stake for k in vals},
        "balances": {k.address: balance for k in accts},
    }
    return genesis, vals, accts


# ----------------------------------------------------------- account transfers
def test_transfer_updates_balances_and_nonce():
    genesis, _, accts = _genesis()
    state = ChainState(genesis)
    a, b = accts[0], accts[1]
    tx = make_tx(a, b.address, 100, 0)
    state.apply_tx(tx)
    # payer debited, payee credited, payer nonce incremented
    assert state.balances[a.address] == 900
    assert state.balances[b.address] == 1100
    assert state.nonces[a.address] == 1
    assert state.nonces.get(b.address, 0) == 0  # recipient nonce untouched


def test_transfer_to_fresh_account_credits_it():
    genesis, _, accts = _genesis(n_accounts=1)
    state = ChainState(genesis)
    newcomer = AccountKey.generate()
    state.apply_tx(make_tx(accts[0], newcomer.address, 250, 0))
    assert state.balances[newcomer.address] == 250
    assert state.balances[accts[0].address] == 750


def test_total_supply_preserved_no_credit_without_debit():
    """A transfer conserves total funds: every credit has a matching debit."""
    genesis, _, accts = _genesis(balance=1000)
    state = ChainState(genesis)
    supply_before = sum(state.balances.values())
    for i in range(5):
        state.apply_tx(make_tx(accts[0], accts[1].address, 100, i))
    state.apply_tx(make_tx(accts[2], accts[0].address, 300, 0))
    supply_after = sum(state.balances.values())
    assert supply_after == supply_before
    assert state.balances[accts[0].address] == 1000 - 500 + 300
    assert state.balances[accts[1].address] == 1000 + 500
    assert state.balances[accts[2].address] == 1000 - 300


def test_nonce_must_be_exact_then_increments():
    genesis, _, accts = _genesis()
    state = ChainState(genesis)
    a, b = accts[0], accts[1]
    # nonce 0 first
    state.apply_tx(make_tx(a, b.address, 1, 0))
    assert state.nonces[a.address] == 1
    # stale nonce rejected
    with pytest.raises(StateError):
        state.apply_tx(make_tx(a, b.address, 1, 0))
    # future nonce rejected (must be sequential)
    with pytest.raises(StateError):
        state.apply_tx(make_tx(a, b.address, 1, 5))
    # correct next nonce accepted
    state.apply_tx(make_tx(a, b.address, 1, 1))
    assert state.nonces[a.address] == 2


def test_replay_of_committed_tx_rejected():
    genesis, _, accts = _genesis()
    state = ChainState(genesis)
    tx = make_tx(accts[0], accts[1].address, 100, 0)
    state.apply_tx(tx)
    with pytest.raises(StateError):  # same tx again: nonce already consumed
        state.apply_tx(tx)


def test_insufficient_funds_rejected():
    genesis, _, accts = _genesis(balance=1000)
    state = ChainState(genesis)
    with pytest.raises(StateError):
        state.apply_tx(make_tx(accts[0], accts[1].address, 10_000, 0))
    # state untouched after the failed transfer
    assert state.balances[accts[0].address] == 1000
    assert state.balances[accts[1].address] == 1000
    assert state.nonces[accts[0].address] == 0


def test_self_transfer_conserves_and_increments_nonce():
    genesis, _, accts = _genesis()
    state = ChainState(genesis)
    a = accts[0]
    state.apply_tx(make_tx(a, a.address, 400, 0))
    assert state.balances[a.address] == 1000  # debit and credit cancel
    assert state.nonces[a.address] == 1


# ------------------------------------------------------------- invalid txs
def test_unsigned_tx_never_applies():
    genesis, _, accts = _genesis()
    state = ChainState(genesis)
    tx = make_tx(accts[0], accts[1].address, 100, 0)
    tx.pop("signature")
    with pytest.raises(StateError):
        state.apply_tx(tx)
    assert state.balances[accts[1].address] == 1000
    assert state.nonces[accts[0].address] == 0


def test_forged_signature_never_applies():
    genesis, _, accts = _genesis()
    state = ChainState(genesis)
    attacker = AccountKey.generate()
    # attacker signs a tx that spends from accts[0]'s address but carries
    # attacker's own pubkey -> address mismatch / invalid signature
    tx = make_tx(attacker, accts[1].address, 100, 0)
    tx["sender"] = accts[0].address  # claim to be the victim
    with pytest.raises(StateError):
        state.apply_tx(tx)
    assert state.balances[accts[0].address] == 1000
    assert state.balances[accts[1].address] == 1000


def test_block_with_one_invalid_tx_applies_nothing():
    """apply_block is all-or-nothing: an invalid tx aborts the whole block,
    so no earlier valid tx in that block can take effect either."""
    genesis, _, accts = _genesis()
    state = ChainState(genesis)
    good = make_tx(accts[0], accts[1].address, 10, 0)
    bad = make_tx(accts[2], accts[1].address, 999_999, 0)  # insufficient funds
    block = make_block(1, 0, "0" * 64, 1.0, accts[0].address, [good, bad], [])
    with pytest.raises(StateError):
        state.apply_block(block)
    # nothing changed: the good tx in the same block is NOT applied
    assert state.balances[accts[0].address] == 1000
    assert state.balances[accts[1].address] == 1000
    assert state.nonces[accts[0].address] == 0


def test_dry_run_does_not_mutate_state():
    genesis, _, accts = _genesis()
    state = ChainState(genesis)
    block = make_block(
        1, 0, "0" * 64, 1.0, accts[0].address,
        [make_tx(accts[0], accts[1].address, 10, 0)], [],
    )
    state.dry_run_block(block)
    assert state.balances[accts[1].address] == 1000  # unchanged
    assert state.nonces[accts[0].address] == 0


# ---------------------------------------------------------------- validators
def test_quorum_threshold():
    genesis, _, _ = _genesis()
    state = ChainState(genesis)
    assert state.total_stake == 400
    assert 300 > state.total_stake * 2 / 3
    assert 200 <= state.total_stake * 2 / 3


def test_slashing_halves_stake_once():
    genesis, vals, _ = _genesis()
    state = ChainState(genesis)
    bad = vals[0]
    v1 = make_vote(bad, PRECOMMIT, 2, 0, "aa" * 32)
    v2 = make_vote(bad, PRECOMMIT, 2, 0, "bb" * 32)
    ev = make_evidence(v1, v2)
    state.apply_evidence(ev)
    assert state.validators[bad.public_hex] == 50
    assert state.slashed[0]["validator"] == bad.public_hex
    state.apply_evidence(ev)  # idempotent: same equivocation not slashed twice
    assert state.validators[bad.public_hex] == 50
    assert len(state.slashed) == 1


def test_slashed_to_zero_loses_voting_power():
    genesis, vals, _ = _genesis(n_validators=4, stake=1)
    state = ChainState(genesis)
    bad = vals[0]
    ev = make_evidence(
        make_vote(bad, PRECOMMIT, 1, 0, "aa" * 32),
        make_vote(bad, PRECOMMIT, 1, 0, "bb" * 32),
    )
    state.apply_evidence(ev)
    assert state.validators[bad.public_hex] == 0
    assert not state.is_validator(bad.public_hex)
    assert bad.public_hex not in state.active_validators()


def test_invalid_evidence_rejected():
    genesis, vals, _ = _genesis()
    state = ChainState(genesis)
    honest = vals[0]
    v = make_vote(honest, PRECOMMIT, 2, 0, "aa" * 32)
    with pytest.raises(StateError):
        state.apply_evidence(make_evidence(v, v))


def test_apply_block_with_evidence_and_transfer():
    genesis, vals, accts = _genesis()
    state = ChainState(genesis)
    bad = vals[1]
    ev = make_evidence(
        make_vote(bad, PRECOMMIT, 1, 0, "aa" * 32),
        make_vote(bad, PRECOMMIT, 1, 0, "bb" * 32),
    )
    block = make_block(
        1, 0, "0" * 64, 1.0, vals[0].public_hex,
        [make_tx(accts[0], accts[1].address, 5, 0)], [ev],
    )
    state.apply_block(block)
    assert state.validators[bad.public_hex] == 50
    assert state.balances[accts[1].address] == 1005
    assert state.nonces[accts[0].address] == 1
