from collections.abc import Callable

from cryptopals.aes import aes_ecb_encrypt, pad_block
from cryptopals.analysis import block_list, random_bytes, unpadded_oracle_secret_length
from cryptopals.conversions import from_base64

SECRET = """
Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg
aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq
dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg
YnkK
"""

# Define this as a global so it's consisent across all invocations
SECRET_KEY = random_bytes(16)


def encryption_oracle(plaintext: bytes) -> bytes:
    plaintext = pad_block(plaintext + from_base64(SECRET))
    return aes_ecb_encrypt(plaintext, SECRET_KEY)


def last_byte_lookup_table(known: bytes) -> dict[bytes, bytes]:
    lookup = {}
    for b in range(256):
        block = known + bytes([b])
        # get first block of ciphertext
        cipher = encryption_oracle(block)[:16]
        lookup[cipher] = bytes([b])
    return lookup


def solve(oracle: Callable[[bytes], bytes]) -> bytes:
    cleartext = b""
    known = b"A" * 15
    len_unknown = unpadded_oracle_secret_length(oracle)
    for i in range(len_unknown):
        lookup = last_byte_lookup_table(known)
        offset = 16 - (1 + (len(cleartext) % 16))
        prefix = b"A" * offset
        target_block = len(cleartext) // 16

        forced_block = block_list(oracle(prefix))[target_block]
        if forced_block not in lookup:
            raise ValueError(
                f"Ciphertext block ({target_block}) matched no candidate at byte {i} (of {len_unknown})"
            )
        uncovered = lookup[forced_block]
        # add the newly uncovered byte to our cleartext
        cleartext += uncovered
        # update the most recent 15 uncovered bytes
        known = known[1:] + uncovered
    return cleartext


if __name__ == "__main__":
    result = solve(encryption_oracle)
    print("cleartext ->")
    print(result)
