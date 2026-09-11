import random
from collections.abc import Callable

from cryptopals.aes import aes_ecb_encrypt, pad_block
from cryptopals.analysis import (
    break_ecb_suffix,
    first_repeated_block_index,
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


def cut_prefix_oracle(
    oracle: Callable[[bytes], bytes], len_prefix: int
) -> Callable[[bytes], bytes]:
    """
    Transform an oracle so that it ignores full blocks containing a prefix
    of the specified length.

    """
    # be careful not to append a wasted extra block prefix is already at a boundary
    fill = (16 - (len_prefix % 16)) % 16
    ignored_bytes = len_prefix + fill

    def trimmed(plaintext: bytes) -> bytes:
        cipher = oracle(b"X" * fill + plaintext)
        return cipher[ignored_bytes:]

    return trimmed


def prefix_length(oracle: Callable[[bytes], bytes]) -> int:
    """Determine length of the random prefix prepended by the provided oracle."""
    for i in range(16):
        attack = b"A" * (32 + i)
        repeat = first_repeated_block_index(oracle(attack))
        if repeat is not None:
            return repeat * 16 - i
    raise ValueError("Could not determine prefix length")


if __name__ == "__main__":
    oracle = cut_prefix_oracle(encryption_oracle, prefix_length(encryption_oracle))
    result = break_ecb_suffix(oracle)
    print("cleartext ->")
    print(result)
    assert result == from_base64(SECRET)
