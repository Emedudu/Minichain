"""Month 2: signed transactions and Merkle trees."""
from minichain.crypto import KeyPair
from minichain.merkle import merkle_proof, merkle_root, verify_proof
from minichain.transaction import transfer

alice, bob = KeyPair(), KeyPair()

tx = transfer(alice, bob.address, 30, nonce=0, fee=1)
print("Transaction id:", tx.txid)
print("Check:", tx.check_format() or "valid")

tx.amount = 300                      # change the amount after signing
print("After changing amount to 300:", tx.check_format())

# Merkle tree over four transactions
txids = [transfer(alice, bob.address, n, nonce=n).txid for n in range(1, 5)]
root = merkle_root(txids)
print("\nMerkle root:", root)

proof = merkle_proof(txids, 2)       # prove the third transaction is included
print("Proof for tx 3 uses", len(proof), "hashes")
print("Proof valid?", verify_proof(txids[2], proof, root))

txids[2] = transfer(alice, bob.address, 99, nonce=3).txid
print("Root after changing tx 3:", merkle_root(txids))
