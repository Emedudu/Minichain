"""Signed transactions in an account-based model."""
import time
from dataclasses import dataclass, field, asdict

from .crypto import KeyPair, address_from_public, canonical, sha256, verify

COINBASE = "COINBASE"


@dataclass
class Transaction:
    sender_public: str          # compressed public key of the sender, or COINBASE
    recipient: str              # 40-hex-character address
    amount: int                 # whole coins
    fee: int = 0                # paid to the miner who includes the transaction
    nonce: int = 0              # sender's transaction counter; stops replay of old transactions
    timestamp: float = field(default_factory=time.time)
    signature: str = ""

    # ----- identity and signing -----
    def body(self) -> dict:
        """Every field except the signature: this is what gets signed."""
        d = asdict(self)
        d.pop("signature")
        return d

    def signing_bytes(self) -> bytes:
        return canonical(self.body())

    @property
    def txid(self) -> str:
        return sha256(canonical(asdict(self)))

    @property
    def sender(self) -> str:
        return COINBASE if self.is_coinbase else address_from_public(self.sender_public)

    @property
    def is_coinbase(self) -> bool:
        return self.sender_public == COINBASE

    def sign(self, keys: KeyPair) -> "Transaction":
        if keys.public_hex != self.sender_public:
            raise ValueError("key does not match sender")
        self.signature = keys.sign(self.signing_bytes())
        return self

    # ----- stateless checks (state checks such as balance live in the chain) -----
    def check_format(self) -> str | None:
        """Return None if well formed and correctly signed, else a reason."""
        if not isinstance(self.amount, int) or self.amount <= 0:
            return "amount must be a positive whole number"
        if not isinstance(self.fee, int) or self.fee < 0:
            return "fee must not be negative"
        if len(self.recipient) != 40:
            return "recipient is not a valid address"
        if self.is_coinbase:
            return None if self.signature == "" and self.fee == 0 else "malformed coinbase"
        if not self.signature:
            return "missing signature"
        if not verify(self.sender_public, self.signing_bytes(), self.signature):
            return "invalid signature"
        return None

    def to_dict(self) -> dict:
        return asdict(self)

    @staticmethod
    def from_dict(d: dict) -> "Transaction":
        return Transaction(**d)

    @staticmethod
    def coinbase(miner: str, amount: int, height: int) -> "Transaction":
        # the height goes in the nonce so every coinbase has a unique txid
        return Transaction(COINBASE, miner, amount, 0, height, time.time())


def transfer(keys: KeyPair, recipient: str, amount: int, nonce: int, fee: int = 0) -> Transaction:
    """Create and sign a transfer from the key holder's address."""
    return Transaction(keys.public_hex, recipient, amount, fee, nonce).sign(keys)
