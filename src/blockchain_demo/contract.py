"""A tiny deterministic contract VM and contract-address derivation.

Contracts are accounts with `code`; their state is a map of 256-bit storage
slots (key -> value, both 32-byte words, committed by a per-contract storage
trie). The VM is deliberately minimal — just enough to demonstrate that a
contract storage slot can be committed in the state root and proved to a light
client — but it is a *real* stack machine:

    PUSH1 v (0x60 v)  push the immediate byte v (0..255) onto the stack
    SSTORE   (0x55)  pop key, pop value; storage[key] = value
    SLOAD    (0x54)  pop key; push storage[key] (0 if unset)
    ADD      (0x01)  pop a, pop b; push (a + b) mod 2^256
    POP      (0x50)  pop the top word
    STOP     (0x00)  halt successfully

Bytecode is a hex string. Execution is bounded by a step limit so a contract
can never run forever; any underflow, out-of-range opcode or exhausted budget
fails the call (which rolls back the whole block, like an invalid tx).

Storage word keys/values are rendered as 64-char hex (32-byte) strings, which
is what the storage trie commits and what a light client asks for.
"""

from __future__ import annotations

from .crypto import sha256_hex

# Opcodes (EVM-aligned where one exists). PUSH1 reads the next byte as an
# immediate literal, so the PUSH range never clashes with the other opcodes.
OP_STOP = 0x00
OP_ADD = 0x01
OP_PUSH1 = 0x60  # push the next byte as a literal 0..255
OP_POP = 0x50
OP_SLOAD = 0x54
OP_SSTORE = 0x55

WORD_MASK = (1 << 256) - 1
MAX_STEPS = 10_000
STACK_LIMIT = 1024


class ContractError(Exception):
    """Raised when contract execution fails (bad opcode/stack/step budget)."""


def word_hex(value: int) -> str:
    """Render an integer as a 32-byte (64 hex-char) storage word."""
    return format(value & WORD_MASK, "064x")


def contract_address(creator: str, nonce: int) -> str:
    """Deterministically derive a contract address from creator + creation nonce.

    H("contract" || creator || nonce), last 20 bytes — the same shape as an
    EOA address, so no one can control a private key for it.
    """
    return sha256_hex(b"contract" + creator.encode() + str(nonce).encode())[-40:]


def run_code(code_hex: str, storage: dict[str, str], calldata: int = 0) -> None:
    """Execute `code_hex` against `storage` in place.

    `storage` maps 64-hex slot key -> 64-hex slot value and is mutated by
    SSTORE. `calldata` is pushed as the initial stack word so a counter-style
    contract can SSTORE it. Deterministic: same code + storage + calldata
    always yields the same storage. Raises ContractError on any fault.
    """
    try:
        code = bytes.fromhex(code_hex)
    except ValueError as exc:
        raise ContractError("contract code is not valid hex") from exc

    stack: list[int] = [calldata & WORD_MASK]
    steps = 0
    pc = 0
    while pc < len(code):
        steps += 1
        if steps > MAX_STEPS:
            raise ContractError("step limit exceeded")
        op = code[pc]
        pc += 1
        if op == OP_PUSH1:
            if pc >= len(code):
                raise ContractError("PUSH1 with no immediate byte")
            _push(stack, code[pc])
            pc += 1
        elif op == OP_STOP:
            return
        elif op == OP_ADD:
            a, b = _pop(stack), _pop(stack)
            _push(stack, (a + b) & WORD_MASK)
        elif op == OP_POP:
            _pop(stack)
        elif op == OP_SSTORE:
            key = word_hex(_pop(stack))
            value = _pop(stack)
            storage[key] = word_hex(value)
        elif op == OP_SLOAD:
            key = word_hex(_pop(stack))
            _push(stack, int(storage.get(key, word_hex(0)), 16))
        else:
            raise ContractError(f"invalid opcode 0x{op:02x} at {pc - 1}")
    # Falling off the end is treated as STOP (a halt with no fault).


def _push(stack: list[int], value: int) -> None:
    if len(stack) >= STACK_LIMIT:
        raise ContractError("stack overflow")
    stack.append(value)


def _pop(stack: list[int]) -> int:
    if not stack:
        raise ContractError("stack underflow")
    return stack.pop()
