import pytest

from blockchain_demo.crypto import KeyPair
from blockchain_demo.state import ChainState, StateError
from blockchain_demo.types import (
    PRECOMMIT,
    make_block,
    make_evidence,
    make_tx,
    make_vote,
)


def _genesis(n_validators=4, stake=100, balance=1000):
    vals = [KeyPair.generate() for _ in range(n_validators)]
    accts = [KeyPair.generate() for _ in range(3)]
    genesis = {
        "chain_id": "test",
        "validators": {k.public_hex: stake for k in vals},
        "balances": {k.public_hex: balance for k in accts},
    }
    return genesis, vals, accts


def test_transfer_and_nonce():
    genesis, _, accts = _genesis()
    state = ChainState(genesis)
    tx = make_tx(accts[0], accts[1].public_hex, 100, 0)
    state.apply_tx(tx)
    assert state.balances[accts[1].public_hex] == 1100
    assert state.nonces[accts[0].public_hex] == 1
    with pytest.raises(StateError):  # replay: nonce already used
        state.apply_tx(tx)


def test_insufficient_funds():
    genesis, _, accts = _genesis()
    state = ChainState(genesis)
    with pytest.raises(StateError):
        state.apply_tx(make_tx(accts[0], accts[1].public_hex, 10_000, 0))


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


def test_apply_block_with_evidence():
    genesis, vals, accts = _genesis()
    state = ChainState(genesis)
    bad = vals[1]
    ev = make_evidence(
        make_vote(bad, PRECOMMIT, 1, 0, "aa" * 32),
        make_vote(bad, PRECOMMIT, 1, 0, "bb" * 32),
    )
    block = make_block(
        1, 0, "0" * 64, 1.0, vals[0].public_hex,
        [make_tx(accts[0], accts[1].public_hex, 5, 0)], [ev],
    )
    state.apply_block(block)
    assert state.validators[bad.public_hex] == 50
    assert state.balances[accts[1].public_hex] == 1005
