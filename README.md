# MiniChain

A simple peer-to-peer blockchain built from scratch in Python for SIWES (Blockchain Development).

## Setup
    pip install cryptography pytest

## Run the tests (39, about 3 seconds)
    python -m pytest -v

## Re-run the experiments in Chapter Five (about 2-3 minutes)
    python experiments/run_experiments.py
Results are written to experiments/results.json. Timings depend on your computer;
counts and pass/fail results do not.

## Layout
- minichain/crypto.py       SHA-256, secp256k1 keys, ECDSA, addresses
- minichain/transaction.py  signed transactions, coinbase
- minichain/merkle.py       Merkle root, proofs
- minichain/block.py        blocks, Proof of Work
- minichain/chain.py        validation rules, state, mempool, fork choice, save/load
- minichain/node.py         TCP nodes, gossip, sync
