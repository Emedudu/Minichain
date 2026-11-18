"""Month 4: mempool, double spending, replay and tamper-proof storage."""
import copy

from minichain.chain import Blockchain, ValidationError
from minichain.crypto import KeyPair
from minichain.transaction import transfer

alice, bob, carol = KeyPair(), KeyPair(), KeyPair()
chain = Blockchain(difficulty=3)
chain.mine_block(alice.address)
chain.mine_block(alice.address)
print("Alice's balance:", chain.state.balance(alice.address))


def submit(label, tx):
    try:
        chain.submit(tx)
        print(f"{label:42} ACCEPTED  (mempool: {len(chain.mempool)})")
    except ValidationError as e:
        print(f"{label:42} REJECTED  {e}")


first = transfer(alice, bob.address, 60, nonce=0, fee=1)
submit("Alice -> Bob, 60 coins", first)
submit("Alice -> Carol, 60 coins (double spend)", transfer(alice, carol.address, 60, nonce=1))

block, _ = chain.mine_block(carol.address)
print(f"Mined block {block.index} with {len(block.transactions) - 1} transfer(s)")
submit("Same Alice -> Bob transaction again", copy.deepcopy(first))

chain.save("chain.json")
text = open("chain.json").read().replace('"amount": 60', '"amount": 6000', 1)
open("chain.json", "w").write(text)
try:
    Blockchain.load("chain.json", difficulty=3)
except ValidationError as e:
    print("Loading edited file:", e)
