import copy
import time

import pytest

from minichain.chain import BLOCK_REWARD, Blockchain, ValidationError
from minichain.crypto import KeyPair, sha256, verify
from minichain.merkle import merkle_proof, merkle_root, verify_proof
from minichain.node import Node
from minichain.transaction import Transaction, transfer

D = 2  # low difficulty keeps the tests fast


@pytest.fixture
def funded():
    """A chain where Alice has mined two blocks (100 coins)."""
    alice, bob = KeyPair(), KeyPair()
    bc = Blockchain(D)
    bc.mine_block(alice.address)
    bc.mine_block(alice.address)
    return bc, alice, bob


# ---------- hashing ----------
def test_sha256_known_value():
    assert sha256(b"abc") == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"


def test_sha256_is_deterministic():
    assert sha256(b"SIWES") == sha256(b"SIWES")


# ---------- keys and signatures ----------
def test_signature_verifies():
    k = KeyPair()
    assert verify(k.public_hex, b"hello", k.sign(b"hello"))


def test_signature_fails_on_changed_message():
    k = KeyPair()
    assert not verify(k.public_hex, b"hellO", k.sign(b"hello"))


def test_signature_fails_with_wrong_key():
    k1, k2 = KeyPair(), KeyPair()
    assert not verify(k2.public_hex, b"hello", k1.sign(b"hello"))


def test_address_is_40_hex_characters():
    a = KeyPair().address
    assert len(a) == 40 and int(a, 16) >= 0


# ---------- transactions ----------
def test_signed_transfer_is_well_formed():
    k, r = KeyPair(), KeyPair()
    assert transfer(k, r.address, 5, 0).check_format() is None


def test_tampered_amount_breaks_signature():
    k, r = KeyPair(), KeyPair()
    tx = transfer(k, r.address, 5, 0)
    tx.amount = 500
    assert tx.check_format() == "invalid signature"


def test_unsigned_transaction_rejected():
    k, r = KeyPair(), KeyPair()
    assert Transaction(k.public_hex, r.address, 5).check_format() == "missing signature"


def test_zero_and_negative_amounts_rejected():
    k, r = KeyPair(), KeyPair()
    assert transfer(k, r.address, 1, 0).check_format() is None
    bad = Transaction(k.public_hex, r.address, 0).sign(k)
    assert "positive" in bad.check_format()


# ---------- Merkle tree ----------
@pytest.mark.parametrize("n", [1, 2, 3, 4, 5, 8, 13, 100])
def test_every_merkle_proof_verifies(n):
    leaves = [sha256(str(i).encode()) for i in range(n)]
    root = merkle_root(leaves)
    for i in range(n):
        assert verify_proof(leaves[i], merkle_proof(leaves, i), root)


def test_merkle_root_changes_when_a_leaf_changes():
    leaves = [sha256(str(i).encode()) for i in range(8)]
    changed = list(leaves)
    changed[5] = sha256(b"tampered")
    assert merkle_root(leaves) != merkle_root(changed)


def test_merkle_proof_rejects_wrong_leaf():
    leaves = [sha256(str(i).encode()) for i in range(8)]
    proof = merkle_proof(leaves, 3)
    assert not verify_proof(sha256(b"fake"), proof, merkle_root(leaves))


# ---------- blocks and chain ----------
def test_genesis_is_identical_on_every_node():
    assert Blockchain(D).tip.hash == Blockchain(D).tip.hash


def test_mined_block_meets_target(funded):
    bc, *_ = funded
    assert all(b.hash.startswith("0" * D) for b in bc.blocks)


def test_mining_pays_the_reward(funded):
    bc, alice, _ = funded
    assert bc.state.balance(alice.address) == 2 * BLOCK_REWARD


def test_valid_chain_validates(funded):
    bc, *_ = funded
    assert bc.validate_chain()[0]


def test_transfer_moves_coins_and_fee(funded):
    bc, alice, bob = funded
    miner = KeyPair()
    bc.submit(transfer(alice, bob.address, 30, 0, fee=2))
    bc.mine_block(miner.address)
    assert bc.state.balance(alice.address) == 68
    assert bc.state.balance(bob.address) == 30
    assert bc.state.balance(miner.address) == BLOCK_REWARD + 2


def test_insufficient_funds_rejected(funded):
    bc, alice, bob = funded
    with pytest.raises(ValidationError, match="insufficient"):
        bc.submit(transfer(alice, bob.address, 1000, 0))


def test_double_spend_in_mempool_rejected(funded):
    bc, alice, bob = funded
    carol = KeyPair()
    bc.submit(transfer(alice, bob.address, 80, 0))
    with pytest.raises(ValidationError):
        bc.submit(transfer(alice, carol.address, 80, 1))   # only 20 left once the first is counted


def test_replay_rejected(funded):
    bc, alice, bob = funded
    tx = transfer(alice, bob.address, 10, 0)
    bc.submit(tx)
    bc.mine_block(alice.address)
    with pytest.raises(ValidationError, match="nonce"):
        bc.submit(copy.deepcopy(tx))


def test_tampered_transaction_in_block_detected(funded):
    bc, alice, bob = funded
    bc.submit(transfer(alice, bob.address, 10, 0))
    bc.mine_block(alice.address)
    bc.blocks[3].transactions[1].amount = 99
    ok, msg, _ = bc.validate_chain()
    assert not ok and "Merkle" in msg


def test_rehashed_tampered_block_breaks_the_link(funded):
    bc, alice, bob = funded
    bc.mine_block(alice.address)
    b = bc.blocks[1]
    b.transactions[0].recipient = KeyPair().address   # redirect the reward to the attacker
    b.merkle = b.compute_merkle()
    b.mine()   # attacker redoes the work for this block only
    ok, msg, _ = bc.validate_chain()
    assert not ok and "previous_hash" in msg


def test_block_without_enough_work_rejected(funded):
    bc, alice, _ = funded
    from minichain.block import Block
    cb = Transaction.coinbase(alice.address, BLOCK_REWARD, bc.height + 1)
    blk = Block(bc.height + 1, bc.tip.hash, [cb], D)
    blk.merkle = blk.compute_merkle()
    blk.nonce = 0
    blk.hash = blk.compute_hash()
    if blk.meets_target():
        pytest.skip("nonce 0 happened to meet the target")
    with pytest.raises(ValidationError, match="target"):
        bc.add_block(blk)


def test_excess_coinbase_rejected(funded):
    bc, alice, _ = funded
    from minichain.block import Block
    cb = Transaction.coinbase(alice.address, BLOCK_REWARD * 10, bc.height + 1)
    blk = Block(bc.height + 1, bc.tip.hash, [cb], D)
    blk.mine()
    with pytest.raises(ValidationError, match="reward"):
        bc.add_block(blk)


def test_mempool_prefers_higher_fees(funded):
    bc, alice, bob = funded
    carol, dave = KeyPair(), KeyPair()
    bc.submit(transfer(alice, carol.address, 10, 0))
    bc.mine_block(dave.address)
    bc.submit(transfer(alice, bob.address, 1, 1, fee=1))
    bc.submit(transfer(carol, bob.address, 1, 0, fee=5))
    picked = bc.select_transactions()
    assert picked[0].fee == 5


def test_save_and_load_round_trip(tmp_path, funded):
    bc, *_ = funded
    p = tmp_path / "chain.json"
    bc.save(p)
    loaded = Blockchain.load(p, D)
    assert loaded.tip.hash == bc.tip.hash and loaded.state.balances == bc.state.balances


def test_tampered_file_refused_on_load(tmp_path, funded):
    bc, *_ = funded
    p = tmp_path / "chain.json"
    bc.save(p)
    p.write_text(p.read_text().replace('"amount": 50', '"amount": 5000', 1))
    with pytest.raises(ValidationError):
        Blockchain.load(p, D)


def test_longer_valid_chain_replaces_shorter(funded):
    bc, alice, _ = funded
    other = Blockchain(D)
    for _ in range(4):
        other.mine_block(alice.address)
    assert bc.replace_chain(other.blocks)
    assert bc.height == 4


def test_shorter_chain_not_adopted(funded):
    bc, alice, _ = funded
    other = Blockchain(D)
    other.mine_block(alice.address)
    assert not bc.replace_chain(other.blocks)


# ---------- networking ----------
def _wait(cond, timeout=10.0):
    end = time.time() + timeout
    while time.time() < end:
        if cond():
            return True
        time.sleep(0.05)
    return False


def test_three_nodes_share_transactions_and_blocks():
    a, b, c = (Node(n, p, D).start() for n, p in [("A", 7101), ("B", 7102), ("C", 7103)])
    try:
        a.connect(b)
        b.connect(c)          # A and C are not directly connected
        alice, bob = KeyPair(), KeyPair()
        a.mine(alice.address)
        assert _wait(lambda: c.chain.height == 1)
        a.submit_transaction(transfer(alice, bob.address, 7, 0))
        assert _wait(lambda: len(c.chain.mempool) == 1)
        c.mine(bob.address)
        assert _wait(lambda: a.chain.height == 2)
        assert a.chain.tip.hash == b.chain.tip.hash == c.chain.tip.hash
        assert a.chain.state.balance(bob.address) == 7 + BLOCK_REWARD
    finally:
        for n in (a, b, c):
            n.stop()


def test_new_node_syncs_full_chain():
    a = Node("A", 7111, D).start()
    z = Node("Z", 7112, D).start()
    try:
        miner = KeyPair()
        for _ in range(5):
            a.mine(miner.address)
        assert z.sync_from(a.port)
        assert z.chain.tip.hash == a.chain.tip.hash and z.chain.height == 5
    finally:
        a.stop()
        z.stop()
