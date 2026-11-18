"""Month 3: Proof of Work mining at increasing difficulty (average of 5 blocks each)."""
import time

from minichain.block import Block
from minichain.crypto import KeyPair
from minichain.transaction import Transaction

miner = KeyPair().address
print(f"{'Difficulty':>10} {'Avg attempts':>13} {'Expected':>10} {'Avg secs':>9}  Last block hash")

for difficulty in range(1, 6):
    attempts, seconds = [], []
    for trial in range(5):
        reward = Transaction.coinbase(miner, 50, height=trial)
        block = Block(1, "0" * 64, [reward], difficulty)
        start = time.perf_counter()
        attempts.append(block.mine())    # try nonces until the hash has enough leading zeros
        seconds.append(time.perf_counter() - start)
    avg = sum(attempts) // 5
    print(f"{difficulty:>10} {avg:>13,} {16 ** difficulty:>10,} "
          f"{sum(seconds) / 5:>9.3f}  {block.hash[:28]}...")

print("\nEach extra zero digit makes mining about 16 times harder,")
print("but checking a block still takes one hash:", block.meets_target())
