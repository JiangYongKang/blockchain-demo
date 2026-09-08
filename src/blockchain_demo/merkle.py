"""Sparse Merkle tree (SMT) and the list Merkle root used in block headers.

Two commitment primitives back the light-client proofs:

* **`SparseMerkleTree`** — a 256-bit sparse Merkle tree over a key/value map.
  The tree has a fixed shape (256 levels, key = SHA-256 path); absent keys
  implicitly map to the empty value, whose leaf hash is a well-known constant.
  This makes *absence* provable: a non-membership proof is just a Merkle
  inclusion proof for the empty value. Leaf and internal nodes are domain
  separated (a leaf hash can never be mistaken for an internal-node hash), and
  every internal node is bound to its level (a subtree hash cannot be replayed
  at a different depth).
* **`merkle_root`** over a list — an ordinary binary Merkle tree for the
  transaction and evidence lists committed in the block header.

Tree levels are numbered 0 (leaf hash) up to 256 (root). An internal node at
level L hashes its two level-(L-1) children; the precomputed `zeros[L]` is the
hash of an entirely empty subtree at level L.

A proof is a list of `[sibling_hash, direction]` pairs running from the leaf
up to the root. Verification recomputes the root purely from the claimed
key/value and the proof — it never touches the tree, so a light client can
check it with only the root it trusts.
"""

from __future__ import annotations

from typing import Optional

from .crypto import sha256_hex

# Tree depth: keys are 256-bit SHA-256 hashes, so there are 256 levels.
DEPTH = 256

# Domain-separation prefixes (kept as bytes so hashing stays one sha256 call).
_LEAF = b"\x00"
_INTERNAL = b"\x01"
_LIST = b"\x02"

# Hash of the empty value: H(LEAF || ""). A key that has never been written
# maps to this leaf. Absence proofs are inclusion proofs for this value.
EMPTY_VALUE = ""
EMPTY_LEAF_HASH = sha256_hex(_LEAF + EMPTY_VALUE.encode())

# zeros[L] = hash of an entirely empty subtree at level L.
# zeros[0] is the empty-leaf hash; zeros[L] = H(INTERNAL, level=L, zeros[L-1] x2).
_zeros: list[str] = [EMPTY_LEAF_HASH]
for _level in range(1, DEPTH + 1):
    _zeros.append(
        sha256_hex(_INTERNAL + _level.to_bytes(2, "big") + bytes.fromhex(_zeros[-1]) * 2)
    )


def _internal_hash(level: int, left: str, right: str) -> str:
    """Hash an internal node at `level` (1 = just above the leaves).

    The level (2-byte) binds the hash to its depth; the INTERNAL prefix separates
    it from leaf hashes. Together these rule out 2nd-preimage and
    subtree-replay confusion.
    """
    return sha256_hex(
        _INTERNAL + level.to_bytes(2, "big") + bytes.fromhex(left) + bytes.fromhex(right)
    )


def leaf_hash(value: str) -> str:
    """Hash a stored value into its leaf node (empty value -> EMPTY_LEAF_HASH)."""
    return sha256_hex(_LEAF + str(value).encode())


def _path_bit(path: bytes, depth: int) -> int:
    """Bit `depth` (0 = root) of a 256-bit path, MSB first."""
    return (path[depth // 8] >> (7 - (depth % 8))) & 1


def _collapse(leaves: list[tuple[bytes, str]], depth: int) -> str:
    """Collapse sorted (path, leaf-hash) pairs into a subtree root.

    `depth` is the root-down bit position of this node (0 = root). The leaves
    must all share the path prefix above `depth`; untouched branches are filled
    from `_zeros`. Returns a node at level DEPTH-depth.
    """
    if not leaves:
        return _zeros[DEPTH - depth]
    if depth == DEPTH:
        return leaves[0][1]  # all pairs here share the full path (same key)
    left, right = [], []
    for path, h in leaves:
        (right if _path_bit(path, depth) else left).append((path, h))
    lh = _collapse(left, depth + 1) if left else _zeros[DEPTH - depth - 1]
    rh = _collapse(right, depth + 1) if right else _zeros[DEPTH - depth - 1]
    return _internal_hash(DEPTH - depth, lh, rh)


class SparseMerkleTree:
    """A 256-bit sparse Merkle tree mapping hex keys -> string values.

    Values are stored verbatim in memory; only their leaf hashes are
    committed. `root`/`prove` never mutate the tree, and `verify_proof` is a
    static method that needs no tree at all.
    """

    def __init__(self, data: Optional[dict[str, str]] = None):
        self._data: dict[str, str] = dict(data or {})

    # ------------------------------------------------------------- accessors
    def get(self, key: str) -> Optional[str]:
        return self._data.get(key)

    def root(self) -> str:
        leaves = sorted((bytes.fromhex(k), leaf_hash(v)) for k, v in self._data.items())
        return _collapse(leaves, 0)

    def update(self, key: str, value: str) -> None:
        """Insert/overwrite a key. Setting the empty value deletes it."""
        if value == EMPTY_VALUE:
            self._data.pop(key, None)
        else:
            self._data[key] = value

    # --------------------------------------------------------------- proofs
    def prove(self, key: str) -> list[list]:
        """Return an inclusion proof for `key`, leaf-up.

        Covers the key's *current* value: for an absent key it is a
        non-membership proof (a path to the empty leaf). Each step is
        `[sibling_hash, direction]`, direction = the key's own path bit at
        that level (0 = key node is the left child, 1 = right child). Step 0
        sits just above the leaf; step 255 is the root.
        """
        path = bytes.fromhex(key)
        present = sorted((bytes.fromhex(k), leaf_hash(v)) for k, v in self._data.items())
        steps: list[list] = []
        group = present
        for depth in range(DEPTH):  # walk root-down, recording sibling subtrees
            bit = _path_bit(path, depth)
            same, sib = [], []
            for p, h in group:
                (same if _path_bit(p, depth) == bit else sib).append((p, h))
            sib_hash = _collapse(sib, depth + 1) if sib else _zeros[DEPTH - depth - 1]
            steps.append([sib_hash, bit])
            group = same
        return steps[::-1]  # flip to leaf-up

    @staticmethod
    def verify_proof(root: str, key: str, value: str, proof: list[list]) -> bool:
        """Recompute the root from (key, value) + proof and compare to `root`.

        Pure function: trusts nothing but `root`. Returns False on any
        malformed proof (wrong length, bad direction, non-hex hash, direction
        inconsistent with the key) or a root mismatch.
        """
        try:
            if len(proof) != DEPTH:
                return False
            path = bytes.fromhex(key)
            node = leaf_hash(value)
            for i in range(DEPTH):  # i = 0 leaf step; the node produced is level i+1
                sibling, bit = proof[i]
                if bit not in (0, 1) or not isinstance(sibling, str):
                    return False
                bytes.fromhex(sibling)  # must be valid hex
                depth = DEPTH - 1 - i   # root-down bit position of this step
                if bit != _path_bit(path, depth):
                    return False  # direction must match the claimed key
                if bit == 0:      # key node is the left child
                    node = _internal_hash(i + 1, node, sibling)
                else:             # key node is the right child
                    node = _internal_hash(i + 1, sibling, node)
            return node == root
        except (ValueError, TypeError, IndexError):
            return False


# ----------------------------------------------------------------- list root
def merkle_root(items: list[str]) -> str:
    """Binary Merkle root over a list of element hashes (hex strings).

    Empty list -> SHA-256 of the empty string. An odd node promotes the lone
    child (no duplication). Items are treated as opaque; callers pass the
    canonical hash of each element.
    """
    if not items:
        return sha256_hex(b"")
    level = list(items)
    while len(level) > 1:
        nxt = []
        for i in range(0, len(level), 2):
            if i + 1 < len(level):
                nxt.append(
                    sha256_hex(_LIST + bytes.fromhex(level[i]) + bytes.fromhex(level[i + 1]))
                )
            else:
                nxt.append(level[i])  # promote the odd node
        level = nxt
    return level[0]
