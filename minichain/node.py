"""A network node: holds a Blockchain and talks to peers over TCP with JSON messages.
Messages: TX (new transaction), BLOCK (new block), GET_CHAIN / CHAIN (full chain for sync)."""
import json
import socket
import socketserver
import threading

from .block import Block
from .chain import Blockchain, ValidationError
from .transaction import Transaction


def _send(host: str, port: int, msg: dict, expect_reply=False):
    with socket.create_connection((host, port), timeout=10) as s:
        s.sendall(json.dumps(msg).encode() + b"\n")
        if expect_reply:
            buf = b""
            while not buf.endswith(b"\n"):
                chunk = s.recv(65536)
                if not chunk:
                    break
                buf += chunk
            return json.loads(buf)
    return None


class Node:
    def __init__(self, name: str, port: int, difficulty: int = 3):
        self.name, self.port = name, port
        self.chain = Blockchain(difficulty)
        self.peers: set[int] = set()
        self.lock = threading.RLock()
        self.log: list[str] = []
        self.messages_received = 0
        node = self

        class Handler(socketserver.StreamRequestHandler):
            def handle(self):
                msg = json.loads(self.rfile.readline())
                reply = node.on_message(msg)
                if reply is not None:
                    self.wfile.write(json.dumps(reply).encode() + b"\n")

        socketserver.ThreadingTCPServer.allow_reuse_address = True
        self.server = socketserver.ThreadingTCPServer(("127.0.0.1", port), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    # ----- lifecycle -----
    def start(self):
        self.thread.start()
        return self

    def stop(self):
        self.server.shutdown()
        self.server.server_close()

    def connect(self, other: "Node"):
        self.peers.add(other.port)
        other.peers.add(self.port)

    # ----- outgoing -----
    def broadcast(self, msg: dict, exclude: int | None = None):
        for p in list(self.peers):
            if p != exclude:
                try:
                    _send("127.0.0.1", p, {**msg, "from": self.port})
                except OSError:
                    self.log.append(f"peer {p} unreachable")

    def submit_transaction(self, tx: Transaction):
        with self.lock:
            self.chain.submit(tx)
        self.broadcast({"type": "TX", "tx": tx.to_dict()})

    def mine(self, miner_address: str) -> Block:
        with self.lock:
            block, _ = self.chain.mine_block(miner_address)
        self.broadcast({"type": "BLOCK", "block": block.to_dict()})
        return block

    def sync_from(self, port: int) -> bool:
        reply = _send("127.0.0.1", port, {"type": "GET_CHAIN", "from": self.port}, expect_reply=True)
        blocks = [Block.from_dict(d) for d in reply["chain"]]
        with self.lock:
            return self.chain.replace_chain(blocks)

    # ----- incoming -----
    def on_message(self, msg: dict):
        self.messages_received += 1
        kind, sender = msg["type"], msg.get("from")
        if kind == "TX":
            tx = Transaction.from_dict(msg["tx"])
            with self.lock:
                if tx.txid in self.chain.mempool:
                    return None             # already seen: stop the gossip here
                try:
                    self.chain.submit(tx)
                except ValidationError as e:
                    self.log.append(f"rejected tx: {e}")
                    return None
            self.broadcast(msg, exclude=sender)
        elif kind == "BLOCK":
            block = Block.from_dict(msg["block"])
            with self.lock:
                if block.index <= self.chain.height and any(b.hash == block.hash for b in self.chain.blocks):
                    return None
                try:
                    self.chain.add_block(block)
                except ValidationError as e:
                    self.log.append(f"block not added directly ({e}); syncing")
                    adopted = False
                else:
                    adopted = True
            if not adopted and sender:
                try:
                    adopted = self.sync_from(sender)
                except OSError:
                    adopted = False
            if adopted:
                self.broadcast(msg, exclude=sender)
        elif kind == "GET_CHAIN":
            with self.lock:
                return {"chain": [b.to_dict() for b in self.chain.blocks]}
        return None
