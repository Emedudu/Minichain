"""Month 1: SHA-256 hashing and digital signatures."""
import hashlib

from minichain.crypto import KeyPair, verify


def sha256(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


# Avalanche effect: one letter changed, a completely different hash
for msg in ["SIWES Blockchain Training", "SIWES Blockchain training"]:
    print(f"{msg:26} -> {sha256(msg)}")

# Key pair, address and signature
keys = KeyPair()
print("\nPublic key:", keys.public_hex)
print("Address:   ", keys.address)

message = b"Send 10 coins to Bob"
signature = keys.sign(message)
print("Signature: ", signature[:48] + "...")

print("\nSignature valid?           ", verify(keys.public_hex, message, signature))
print("Valid for a changed message?", verify(keys.public_hex, b"Send 99 coins to Bob", signature))
