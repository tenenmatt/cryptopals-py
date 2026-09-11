import random

from cryptopals.aes import aes_ecb_encrypt, pad_block
from cryptopals.analysis import (
    break_ecb_suffix,
    oracle_without_prefix,
    prefix_length,
    random_bytes,
)
from cryptopals.conversions import from_base64

SECRET = """
Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg
aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq
dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg
YnkK
"""

# Define this as a global so it's consisent across all invocations
SECRET_KEY = random_bytes(16)
MIN_PREFIX = 0
MAX_PREFIX = 42
RANDOM_PREFIX = random_bytes(random.randint(MIN_PREFIX, MAX_PREFIX))


# This differs from challenge 12 oracle exactly by prepending RANDOM_PREFIX
def encryption_oracle(plaintext: bytes) -> bytes:
    plaintext = pad_block(RANDOM_PREFIX + plaintext + from_base64(SECRET))
    return aes_ecb_encrypt(plaintext, SECRET_KEY)


if __name__ == "__main__":
    # Convert challenge 14 oracle into the oracle from 12, by using prefix_length to work out the size
    # of the random (hidden) prefix and then ignoring the blocks that contain that prefix.
    # The resulting oracle produces ciphertext starting with the plaintext it's called with (just like 12).
    oracle = oracle_without_prefix(encryption_oracle, prefix_length(encryption_oracle))
    result = break_ecb_suffix(oracle)
    print("cleartext ->")
    print(result)
    assert result == from_base64(SECRET)
