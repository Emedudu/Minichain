"""Blocks: a header that is hashed and mined, and a body of transactions."""
import time
from dataclasses import dataclass, field

from .crypto import canonical, sha256
from .merkle import merkle_root
from .transaction import Transaction


@dataclass
class Block:
    index: int
    previous_hash: str
    transactions: list[Transaction]
    difficulty: int                 # number of leading zero hex digits the hash must have
    timestamp: float = field(default_factory=time.time)
    nonce: int = 0
    merkle: str = ""
    hash: str = ""

    def header(self) -> dict:
        return {
            "index": self.index,
            "previous_hash": self.previous_hash,
            "merkle_root": self.merkle,
            "timestamp": self.timestamp,
            "difficulty": self.difficulty,
            "nonce": self.nonce,
        }

    def compute_hash(self) -> str:
        return sha256(canonical(self.header()))

    def compute_merkle(self) -> str:
        return merkle_root([tx.txid for tx in self.transactions])

    def meets_target(self, h: str | None = None) -> bool:
        return (h or self.hash).startswith("0" * self.difficulty)

    def mine(self) -> int:
        """Proof of Work: try nonces until the header hash has enough leading zeros.
        Returns the number of hashes tried."""
        self.merkle = self.compute_merkle()
        self.nonce = 0
        while True:
            h = self.compute_hash()
            if self.meets_target(h):
                self.hash = h
                return self.nonce + 1
            self.nonce += 1

    def to_dict(self) -> dict:
        return {**self.header(), "hash": self.hash,
                "transactions": [tx.to_dict() for tx in self.transactions]}

    @staticmethod
    def from_dict(d: dict) -> "Block":
        return Block(d["index"], d["previous_hash"],
                     [Transaction.from_dict(t) for t in d["transactions"]],
                     d["difficulty"], d["timestamp"], d["nonce"], d["merkle_root"], d["hash"])
