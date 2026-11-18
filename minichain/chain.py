"""The blockchain: validation rules, account state, mempool, mining, persistence, fork choice."""
import json
from pathlib import Path

from .block import Block
from .transaction import Transaction

BLOCK_REWARD = 50
MAX_TXS_PER_BLOCK = 100


class ValidationError(Exception):
    pass


def genesis_block(difficulty: int) -> Block:
    """Fixed first block, the same on every node."""
    g = Block(0, "0" * 64, [], difficulty, timestamp=0.0)
    g.mine()
    return g


class State:
    """Account balances and nonces derived by replaying every block from genesis."""

    def __init__(self):
        self.balances: dict[str, int] = {}
        self.nonces: dict[str, int] = {}

    def copy(self) -> "State":
        s = State()
        s.balances, s.nonces = dict(self.balances), dict(self.nonces)
        return s

    def balance(self, addr: str) -> int:
        return self.balances.get(addr, 0)

    def nonce(self, addr: str) -> int:
        return self.nonces.get(addr, 0)

    def check(self, tx: Transaction) -> str | None:
        """State rules for a non-coinbase transaction: right nonce, enough funds."""
        if tx.nonce != self.nonce(tx.sender):
            return f"wrong nonce (expected {self.nonce(tx.sender)}, got {tx.nonce}): replay or out of order"
        if self.balance(tx.sender) < tx.amount + tx.fee:
            return "insufficient funds"
        return None

    def apply(self, tx: Transaction, miner: str | None = None):
        if not tx.is_coinbase:
            self.balances[tx.sender] = self.balance(tx.sender) - tx.amount - tx.fee
            self.nonces[tx.sender] = self.nonce(tx.sender) + 1
            if miner and tx.fee:
                self.balances[miner] = self.balance(miner) + tx.fee
        self.balances[tx.recipient] = self.balance(tx.recipient) + tx.amount


class Blockchain:
    def __init__(self, difficulty: int = 3):
        self.difficulty = difficulty
        self.blocks: list[Block] = [genesis_block(difficulty)]
        self.state = State()
        self.mempool: dict[str, Transaction] = {}

    # ---------------- reading ----------------
    @property
    def tip(self) -> Block:
        return self.blocks[-1]

    @property
    def height(self) -> int:
        return len(self.blocks) - 1

    def work(self) -> int:
        """Cumulative Proof of Work: each block with difficulty d costs about 16**d hashes."""
        return sum(16 ** b.difficulty for b in self.blocks)

    # ---------------- block validation ----------------
    def _validate_block(self, block: Block, prev: Block, state: State) -> State:
        """Check one block against its predecessor and the state before it.
        Returns the new state; raises ValidationError with the first rule broken."""
        if block.index != prev.index + 1:
            raise ValidationError(f"block {block.index}: index does not follow {prev.index}")
        if block.previous_hash != prev.hash:
            raise ValidationError(f"block {block.index}: previous_hash does not match block {prev.index}")
        if block.difficulty != self.difficulty:
            raise ValidationError(f"block {block.index}: wrong difficulty")
        if block.compute_merkle() != block.merkle:
            raise ValidationError(f"block {block.index}: Merkle root does not match its transactions")
        if block.compute_hash() != block.hash:
            raise ValidationError(f"block {block.index}: stored hash does not match header")
        if not block.meets_target():
            raise ValidationError(f"block {block.index}: hash does not meet the difficulty target")
        if not block.transactions or not block.transactions[0].is_coinbase:
            raise ValidationError(f"block {block.index}: first transaction must be the coinbase")
        if len(block.transactions) > MAX_TXS_PER_BLOCK + 1:
            raise ValidationError(f"block {block.index}: too many transactions")

        new = state.copy()
        seen, fees = set(), 0
        miner = block.transactions[0].recipient
        for tx in block.transactions:
            if tx.txid in seen:
                raise ValidationError(f"block {block.index}: duplicate transaction")
            seen.add(tx.txid)
            reason = tx.check_format()
            if reason:
                raise ValidationError(f"block {block.index}: {reason}")
            if tx.is_coinbase:
                if tx is not block.transactions[0]:
                    raise ValidationError(f"block {block.index}: extra coinbase")
                continue
            reason = new.check(tx)
            if reason:
                raise ValidationError(f"block {block.index}: {reason}")
            new.apply(tx, miner)
            fees += tx.fee
        cb = block.transactions[0]
        if cb.amount > BLOCK_REWARD:
            raise ValidationError(f"block {block.index}: coinbase pays more than the block reward")
        new.apply(cb)
        return new

    def validate_chain(self, blocks: list[Block] | None = None) -> tuple[bool, str, State | None]:
        """Re-check every block from genesis. Returns (ok, message, final state)."""
        blocks = blocks if blocks is not None else self.blocks
        g = genesis_block(self.difficulty)
        if blocks[0].hash != g.hash:
            return False, "genesis block does not match", None
        state = State()
        try:
            for prev, block in zip(blocks, blocks[1:]):
                state = self._validate_block(block, prev, state)
        except ValidationError as e:
            return False, str(e), None
        return True, f"valid: {len(blocks)} blocks", state

    def add_block(self, block: Block) -> None:
        self.state = self._validate_block(block, self.tip, self.state)
        self.blocks.append(block)
        for tx in block.transactions:
            self.mempool.pop(tx.txid, None)
        self._revalidate_mempool()

    # ---------------- mempool and mining ----------------
    def _pending_state(self) -> State:
        s = self.state.copy()
        for tx in self.mempool.values():
            s.apply(tx)
        return s

    def submit(self, tx: Transaction) -> None:
        """Accept a transaction into the mempool, or raise ValidationError."""
        reason = tx.check_format()
        if not reason and tx.is_coinbase:
            reason = "coinbase transactions cannot be submitted"
        if not reason and tx.txid in self.mempool:
            reason = "already in mempool"
        if not reason:
            reason = self._pending_state().check(tx)
        if reason:
            raise ValidationError(reason)
        self.mempool[tx.txid] = tx

    def _revalidate_mempool(self):
        pending, self.mempool = list(self.mempool.values()), {}
        for tx in sorted(pending, key=lambda t: (t.sender, t.nonce)):
            try:
                self.submit(tx)
            except ValidationError:
                pass

    def select_transactions(self) -> list[Transaction]:
        """Highest fee first, but each sender's transactions stay in nonce order."""
        s, chosen = self.state.copy(), []
        remaining = sorted(self.mempool.values(), key=lambda t: (-t.fee, t.timestamp))
        progress = True
        while progress and len(chosen) < MAX_TXS_PER_BLOCK:
            progress = False
            for tx in list(remaining):
                if s.check(tx) is None:
                    s.apply(tx)
                    chosen.append(tx)
                    remaining.remove(tx)
                    progress = True
                    if len(chosen) == MAX_TXS_PER_BLOCK:
                        break
        return chosen

    def mine_block(self, miner: str) -> tuple[Block, int]:
        txs = self.select_transactions()
        cb = Transaction.coinbase(miner, BLOCK_REWARD, self.height + 1)
        block = Block(self.height + 1, self.tip.hash, [cb] + txs, self.difficulty)
        attempts = block.mine()
        self.add_block(block)
        return block, attempts

    # ---------------- fork choice ----------------
    def replace_chain(self, blocks: list[Block]) -> bool:
        """Adopt a competing chain only if it is fully valid and has more cumulative work."""
        ok, _, state = self.validate_chain(blocks)
        if not ok or sum(16 ** b.difficulty for b in blocks) <= self.work():
            return False
        old_txs = [tx for b in self.blocks[1:] for tx in b.transactions if not tx.is_coinbase]
        self.blocks, self.state = blocks, state
        for tx in old_txs:          # transactions dropped from the old chain go back to the mempool
            self.mempool[tx.txid] = tx
        self._revalidate_mempool()
        return True

    # ---------------- persistence ----------------
    def save(self, path: str | Path) -> None:
        Path(path).write_text(json.dumps([b.to_dict() for b in self.blocks]))

    @classmethod
    def load(cls, path: str | Path, difficulty: int = 3) -> "Blockchain":
        bc = cls(difficulty)
        blocks = [Block.from_dict(d) for d in json.loads(Path(path).read_text())]
        ok, msg, state = bc.validate_chain(blocks)
        if not ok:
            raise ValidationError(f"stored chain rejected: {msg}")
        bc.blocks, bc.state = blocks, state
        return bc
