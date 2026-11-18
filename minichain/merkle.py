"""Merkle tree over transaction ids: root, inclusion proof, proof check.
An odd node at any level is paired with itself, as in Bitcoin."""
from .crypto import sha256


def _parent(left: str, right: str) -> str:
    return sha256(bytes.fromhex(left) + bytes.fromhex(right))


def merkle_root(leaves: list[str]) -> str:
    if not leaves:
        return "0" * 64
    level = list(leaves)
    while len(level) > 1:
        if len(level) % 2:
            level.append(level[-1])
        level = [_parent(level[i], level[i + 1]) for i in range(0, len(level), 2)]
    return level[0]


def merkle_proof(leaves: list[str], index: int) -> list[tuple[str, str]]:
    """Sibling hashes from leaf to root; each step says whether the sibling is on the left or right."""
    proof, level, i = [], list(leaves), index
    while len(level) > 1:
        if len(level) % 2:
            level.append(level[-1])
        sibling = i ^ 1
        proof.append((level[sibling], "left" if sibling < i else "right"))
        level = [_parent(level[k], level[k + 1]) for k in range(0, len(level), 2)]
        i //= 2
    return proof


def verify_proof(leaf: str, proof: list[tuple[str, str]], root: str) -> bool:
    h = leaf
    for sibling, side in proof:
        h = _parent(sibling, h) if side == "left" else _parent(h, sibling)
    return h == root
