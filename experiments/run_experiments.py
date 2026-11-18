"""Experiments reported in Chapter Five. Writes results.json next to this file."""
import copy
import json
import os
import platform
import random
import statistics as st
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from minichain.block import Block
from minichain.chain import BLOCK_REWARD, Blockchain, ValidationError
from minichain.crypto import KeyPair, canonical, sha256, verify
from minichain.merkle import merkle_proof, merkle_root, verify_proof
from minichain.node import Node
from minichain.transaction import Transaction, transfer

random.seed(2026)
R = {"machine": {"python": platform.python_version(), "cpu_count": os.cpu_count(),
                 "platform": platform.platform()}}


def bits_differ(h1, h2):
    return bin(int(h1, 16) ^ int(h2, 16)).count("1")


# ---------- E1: avalanche effect ----------
diffs = []
alphabet = "abcdefghijklmnopqrstuvwxyz0123456789"
for _ in range(1000):
    msg = "".join(random.choice(alphabet) for _ in range(32))
    pos = random.randrange(32)
    new_char = random.choice([c for c in alphabet if c != msg[pos]])
    msg2 = msg[:pos] + new_char + msg[pos + 1:]
    diffs.append(bits_differ(sha256(msg.encode()), sha256(msg2.encode())))
hist = {}
for d in diffs:
    b = (d // 8) * 8
    hist[b] = hist.get(b, 0) + 1
R["avalanche"] = {
    "pairs": len(diffs), "mean_bits": round(st.mean(diffs), 2), "mean_pct": round(st.mean(diffs) / 256 * 100, 2),
    "stdev": round(st.stdev(diffs), 2), "min": min(diffs), "max": max(diffs),
    "histogram_8bit_bins": {str(k): hist[k] for k in sorted(hist)},
    "example": {"m1": "SIWES Blockchain Training",
                "h1": sha256(b"SIWES Blockchain Training"),
                "m2": "SIWES Blockchain training",
                "h2": sha256(b"SIWES Blockchain training"),
                "bits": bits_differ(sha256(b"SIWES Blockchain Training"), sha256(b"SIWES Blockchain training"))},
}
print("E1 avalanche", R["avalanche"]["mean_bits"])

# ---------- E2: hashing and signature speed ----------
hdr = Block(1, "0" * 64, [], 3).header()
n = 200_000
t = time.perf_counter()
for i in range(n):
    hdr["nonce"] = i
    sha256(canonical(hdr))
header_rate = n / (time.perf_counter() - t)
raw = b"x" * 200
t = time.perf_counter()
for _ in range(n):
    sha256(raw)
raw_rate = n / (time.perf_counter() - t)
k = KeyPair()
msgs = [os.urandom(100) for _ in range(500)]
t = time.perf_counter()
keys = [KeyPair() for _ in range(500)]
keygen_ms = (time.perf_counter() - t) / 500 * 1000
t = time.perf_counter()
sigs = [k.sign(m) for m in msgs]
sign_ms = (time.perf_counter() - t) / 500 * 1000
t = time.perf_counter()
ok = all(verify(k.public_hex, m, s) for m, s in zip(msgs, sigs))
verify_ms = (time.perf_counter() - t) / 500 * 1000
R["speed"] = {"block_header_hashes_per_sec": round(header_rate), "raw_sha256_per_sec": round(raw_rate),
              "keygen_ms": round(keygen_ms, 3), "sign_ms": round(sign_ms, 3), "verify_ms": round(verify_ms, 3),
              "all_verified": ok, "sig_len_bytes_mean": round(st.mean(len(s) / 2 for s in sigs), 1),
              "pubkey_bytes": len(k.public_hex) // 2}
print("E2 speed", R["speed"])

# ---------- E3: Proof of Work vs difficulty ----------
pow_rows = []
miner = KeyPair().address
for d in range(1, 6):
    trials = 20 if d <= 4 else 10
    attempts, times = [], []
    for i in range(trials):
        cb = Transaction.coinbase(miner, BLOCK_REWARD, 1)
        cb.timestamp = 1_790_000_000 + d * 1000 + i     # vary the block so each trial is a fresh puzzle
        b = Block(1, "0" * 64, [cb], d, timestamp=1_790_000_000 + d * 1000 + i)
        t = time.perf_counter()
        a = b.mine()
        times.append(time.perf_counter() - t)
        attempts.append(a)
    pow_rows.append({"difficulty": d, "trials": trials, "expected_attempts": 16 ** d,
                     "mean_attempts": round(st.mean(attempts)), "median_attempts": round(st.median(attempts)),
                     "min_attempts": min(attempts), "max_attempts": max(attempts),
                     "mean_seconds": round(st.mean(times), 4), "max_seconds": round(max(times), 3)})
    print("E3 pow", pow_rows[-1])
R["pow"] = pow_rows

# ---------- E4: Merkle proof size ----------
mrows = []
for n in [1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024]:
    leaves = [sha256(os.urandom(16)) for _ in range(n)]
    root = merkle_root(leaves)
    proofs = [merkle_proof(leaves, i) for i in range(n)]
    allok = all(verify_proof(leaves[i], proofs[i], root) for i in range(n))
    plen = max(len(p) for p in proofs)
    mrows.append({"transactions": n, "proof_hashes": plen, "proof_bytes": plen * 32,
                  "all_txids_bytes": n * 32, "all_verified": allok})
leaves = [sha256(str(i).encode()) for i in range(8)]
tampered = list(leaves)
tampered[5] = sha256(b"altered")
R["merkle"] = {"rows": mrows, "root_8": merkle_root(leaves), "root_8_tampered": merkle_root(tampered),
               "fake_leaf_rejected": not verify_proof(sha256(b"fake"), merkle_proof(leaves, 3), merkle_root(leaves))}
print("E4 merkle done")

# ---------- E5: transaction validation cases ----------
DIFF = 3
bc = Blockchain(DIFF)
alice, bob, carol, mallory = KeyPair(), KeyPair(), KeyPair(), KeyPair()
bc.mine_block(alice.address)
bc.mine_block(alice.address)            # Alice now has 100
cases = []


def case(name, fn):
    try:
        fn()
        cases.append({"case": name, "result": "Accepted", "reason": ""})
    except ValidationError as e:
        cases.append({"case": name, "result": "Rejected", "reason": str(e)})


tx_ok = transfer(alice, bob.address, 30, 0, fee=1)
case("Valid transfer: Alice sends 30 to Bob (fee 1)", lambda: bc.submit(tx_ok))
bad_sig = transfer(alice, carol.address, 10, 1)
bad_sig.amount = 90
case("Amount changed after signing (10 to 90)", lambda: bc.submit(bad_sig))
forged = Transaction(alice.public_hex, mallory.address, 50, 0, 1)
forged.signature = mallory.sign(forged.signing_bytes())
case("Mallory signs a transfer from Alice's account", lambda: bc.submit(forged))
case("Alice spends 500 with a balance of 100", lambda: bc.submit(transfer(alice, carol.address, 500, 1)))
case("Double spend: second transfer of 70 before the first is mined (only 69 left)",
     lambda: bc.submit(transfer(alice, carol.address, 70, 1)))
case("Unsigned transaction", lambda: bc.submit(Transaction(alice.public_hex, carol.address, 5, 0, 1)))
case("Negative amount", lambda: bc.submit(Transaction(alice.public_hex, carol.address, -5, 0, 1).sign(alice)))
case("Coinbase submitted by a user", lambda: bc.submit(Transaction.coinbase(mallory.address, 50, 9)))
bc.mine_block(carol.address)
case("Replay: the mined Alice-to-Bob transaction sent again", lambda: bc.submit(copy.deepcopy(tx_ok)))
case("Bob sends 10 to Carol after receiving 30", lambda: bc.submit(transfer(bob, carol.address, 10, 0)))
R["validation_cases"] = cases
for c in cases:
    print("E5", c)

# ---------- E6: tamper detection and validation cost ----------
bc = Blockchain(DIFF)
users = [KeyPair() for _ in range(5)]
nonces = {u.address: 0 for u in users}
for u in users:
    bc.mine_block(u.address)
for _ in range(15):
    for _ in range(4):
        s, r = random.sample(users, 2)
        if bc._pending_state().balance(s.address) > 3:
            bc.submit(transfer(s, r.address, random.randint(1, 3), nonces[s.address], fee=random.randint(0, 2)))
            nonces[s.address] += 1
    bc.mine_block(random.choice(users).address)
R["chain_built"] = {"blocks": len(bc.blocks), "transactions": sum(len(b.transactions) for b in bc.blocks),
                    "transfers": sum(len(b.transactions) - 1 for b in bc.blocks[1:])}
ok, msg, _ = bc.validate_chain()
tamper = [{"attack": "None (untouched chain)", "detected": not ok, "message": msg}]


def attack(name, mutate):
    blocks = copy.deepcopy(bc.blocks)
    mutate(blocks)
    ok, msg, _ = bc.validate_chain(blocks)
    tamper.append({"attack": name, "detected": not ok, "message": msg})


def change_amount(bl):
    blk = next(b for b in bl[1:] if len(b.transactions) > 1)
    blk.transactions[1].amount += 100


def change_amount_fix_merkle(bl):
    blk = next(b for b in bl[1:] if len(b.transactions) > 1)
    blk.transactions[1].amount += 100
    blk.merkle = blk.compute_merkle()


def reroute_reward_remine(bl):
    blk = bl[8]
    blk.transactions[0].recipient = mallory.address
    blk.mine()


def delete_tx(bl):
    blk = next(b for b in bl[1:] if len(b.transactions) > 2)
    del blk.transactions[1]
    blk.mine()


def reorder_blocks(bl):
    bl[5], bl[6] = bl[6], bl[5]


def inflate_reward(bl):
    blk = bl[-1]
    blk.transactions[0].amount = 5000
    blk.mine()


def fake_nonce(bl):
    blk = bl[10]
    blk.nonce += 1
    blk.hash = blk.compute_hash()


attack("Change a transfer amount in a past block", change_amount)
attack("Change an amount and recompute the Merkle root", change_amount_fix_merkle)
attack("Redirect a mining reward and re-mine that block", reroute_reward_remine)
attack("Delete a transaction and re-mine that block", delete_tx)
attack("Swap the order of two blocks", reorder_blocks)
attack("Raise the latest block reward to 5,000 and re-mine", inflate_reward)
attack("Change a nonce and store the new hash", fake_nonce)
R["tamper"] = tamper
for x in tamper:
    print("E6", x)

# re-mining cost after a tamper: how many blocks must be redone
target_block = 5
redo = bc.height - target_block + 1
R["remine_cost"] = {"tampered_block": target_block, "chain_height": bc.height, "blocks_to_redo": redo,
                    "expected_hashes": redo * 16 ** DIFF,
                    "seconds_at_measured_rate": round(redo * 16 ** DIFF / header_rate, 3),
                    "note": "the honest network keeps adding blocks while the attacker re-mines"}

vrows = []
for n_blocks in [10, 25, 50, 100, 200]:
    c = Blockchain(2)
    us = [KeyPair() for _ in range(4)]
    nn = {u.address: 0 for u in us}
    for u in us:
        c.mine_block(u.address)
    while c.height < n_blocks:
        for _ in range(5):
            s, r = random.sample(us, 2)
            if c._pending_state().balance(s.address) > 2:
                c.submit(transfer(s, r.address, 1, nn[s.address]))
                nn[s.address] += 1
        c.mine_block(random.choice(us).address)
    txs = sum(len(b.transactions) for b in c.blocks)
    t = time.perf_counter()
    for _ in range(3):
        assert c.validate_chain()[0]
    vrows.append({"blocks": n_blocks, "transactions": txs,
                  "validate_ms": round((time.perf_counter() - t) / 3 * 1000, 1)})
    print("E6 validate", vrows[-1])
R["validate_cost"] = vrows

# ---------- E7: persistence ----------
p = Path(__file__).with_name("chain_saved.json")
bc.save(p)
size = p.stat().st_size
t = time.perf_counter()
loaded = Blockchain.load(p, DIFF)
load_ms = (time.perf_counter() - t) * 1000
same = loaded.tip.hash == bc.tip.hash and loaded.state.balances == bc.state.balances
p.write_text(p.read_text().replace('"amount": 1,', '"amount": 1000,', 1))
try:
    Blockchain.load(p, DIFF)
    refused = False
    refused_msg = ""
except ValidationError as e:
    refused, refused_msg = True, str(e)
p.unlink()
R["persistence"] = {"blocks": len(bc.blocks), "file_kb": round(size / 1024, 1), "load_ms": round(load_ms, 1),
                    "identical_after_reload": same, "edited_file_refused": refused, "refusal": refused_msg}
print("E7", R["persistence"])


# ---------- E8: five-node network ----------
def wait(cond, timeout=20.0):
    t0 = time.perf_counter()
    while time.perf_counter() - t0 < timeout:
        if cond():
            return time.perf_counter() - t0
        time.sleep(0.002)
    return None


names = ["A", "B", "C", "D", "E"]
nodes = {n: Node(n, 7200 + i, DIFF).start() for i, n in enumerate(names)}
links = [("A", "B"), ("B", "C"), ("C", "D"), ("D", "E"), ("E", "A"), ("A", "C")]
for x, y in links:
    nodes[x].connect(nodes[y])
try:
    alice, bob = KeyPair(), KeyPair()
    blk_times, tx_times = [], []
    for round_ in range(10):
        with nodes["A"].lock:
            blk, _ = nodes["A"].chain.mine_block(alice.address)    # mine first, then time only the spread
        h = nodes["A"].chain.height
        t0 = time.perf_counter()
        nodes["A"].broadcast({"type": "BLOCK", "block": blk.to_dict()})
        wait(lambda: all(nodes[n].chain.height == h for n in names))
        blk_times.append((time.perf_counter() - t0) * 1000)
    for round_ in range(10):
        t0 = time.perf_counter()
        tx = transfer(alice, bob.address, 1, round_)
        nodes["D"].submit_transaction(tx)
        wait(lambda: all(tx.txid in nodes[n].chain.mempool for n in names))
        tx_times.append((time.perf_counter() - t0) * 1000)
    msgs_before = sum(nodes[n].messages_received for n in names)
    nodes["C"].mine(bob.address)
    wait(lambda: all(nodes[n].chain.height == 11 for n in names))
    time.sleep(0.3)
    msgs_for_block = sum(nodes[n].messages_received for n in names) - msgs_before
    consistent = len({nodes[n].chain.tip.hash for n in names}) == 1
    bal = {n: nodes[n].chain.state.balance(bob.address) for n in names}
    # new node joins and syncs
    z = Node("F", 7299, DIFF).start()
    t0 = time.perf_counter()
    synced = z.sync_from(nodes["B"].port)
    sync_ms = (time.perf_counter() - t0) * 1000
    z_ok = z.chain.tip.hash == nodes["A"].chain.tip.hash
    z.stop()
    R["network"] = {"nodes": names, "links": ["-".join(l) for l in links],
                    "block_propagation_ms_mean": round(st.mean(blk_times), 1),
                    "block_propagation_ms_max": round(max(blk_times), 1),
                    "block_mining_note": "time from broadcast until all five nodes hold the block",
                    "tx_propagation_ms_mean": round(st.mean(tx_times), 1),
                    "tx_propagation_ms_max": round(max(tx_times), 1),
                    "messages_for_one_block": msgs_for_block,
                    "all_tips_identical": consistent, "bob_balance_on_each_node": bal,
                    "new_node_sync": {"blocks": z.chain.height + 1, "adopted": synced, "ms": round(sync_ms, 1),
                                      "matches_network": z_ok}}
    print("E8", R["network"])
finally:
    for n in nodes.values():
        n.stop()

# ---------- E9: fork and recovery ----------
p1, p2 = Node("P", 7301, DIFF).start(), Node("Q", 7302, DIFF).start()
try:
    alice, bob = KeyPair(), KeyPair()
    p1.connect(p2)
    p1.mine(alice.address)
    p1.mine(alice.address)
    wait(lambda: p2.chain.height == 2)
    # partition: they stop talking
    p1.peers.clear()
    p2.peers.clear()
    t_on_short = transfer(alice, bob.address, 25, 0)
    p1.submit_transaction(t_on_short)
    p1.mine(alice.address)                          # P: height 3
    for _ in range(3):
        p2.mine(bob.address)                        # Q: height 5
    before = {"P_height": p1.chain.height, "Q_height": p2.chain.height,
              "P_tip": p1.chain.tip.hash[:12], "Q_tip": p2.chain.tip.hash[:12]}
    p1.connect(p2)
    adopted = p1.sync_from(p2.port)
    after = {"P_height": p1.chain.height, "P_tip": p1.chain.tip.hash[:12],
             "tx_back_in_mempool": t_on_short.txid in p1.chain.mempool}
    p1.mine(alice.address)
    wait(lambda: p2.chain.height == 6)
    final = {"heights": [p1.chain.height, p2.chain.height],
             "same_tip": p1.chain.tip.hash == p2.chain.tip.hash,
             "bob_balance": p2.chain.state.balance(bob.address)}
    R["fork"] = {"before_reconnect": before, "adopted_longer_chain": adopted, "after_sync": after, "after_next_block": final}
    print("E9", R["fork"])
finally:
    p1.stop()
    p2.stop()

Path(__file__).with_name("results.json").write_text(json.dumps(R, indent=2))
print("saved")
