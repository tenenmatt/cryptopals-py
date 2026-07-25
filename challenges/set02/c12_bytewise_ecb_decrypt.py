from cryptopals.aes import aes_ecb_encrypt, pad_block
from cryptopals.analysis import block_list, pprint, random_bytes, unpadded_oracle_secret_length
from cryptopals.conversions import from_base64

SECRET = """
Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg
aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq
dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg
YnkK
"""

# Define this as a global so it's consisent across all invocations
SECRET_KEY = random_bytes(16)
ONE_BYTE_SHORT = b"A" * 15


def encryption_oracle(plaintext: bytes) -> bytes:
    plaintext = pad_block(plaintext + from_base64(SECRET))
    return aes_ecb_encrypt(plaintext, SECRET_KEY)


def last_byte_lookup_table(known: bytes = ONE_BYTE_SHORT) -> dict[bytes, bytes]:
    lookup = {}
    for b in range(256):
        block = known + bytes([b])
        # get first block of ciphertext
        cipher = encryption_oracle(block)[:16]
        lookup[cipher] = bytes([b])
    return lookup


if __name__ == "__main__":
    known = ONE_BYTE_SHORT
    lookup = last_byte_lookup_table(known)
    forced_block = encryption_oracle(known)[:16]
    first_byte = lookup[forced_block]
    print(f"First unknown byte: {first_byte}")

    # Now we know the first byte, so we can calculate a new lookup table
    # with "A*14 + that byte", and pass in A*14 to place the next
    # unknown byte in the last position of the block.
    #
    # Eventually we'll have to start looking at later blocks,
    # where the block consists of the last 15 discovered bytes
    # and the next unknown byte in the last position. We must
    # pass in a variable length string to line up that byte
    # correctly, as we continue to uncover bytes in the string.

    cleartext = b""
    known = ONE_BYTE_SHORT
    len_unknown = unpadded_oracle_secret_length(encryption_oracle)
    for i in range(len_unknown):
        lookup = last_byte_lookup_table(known)
        offset = 16 - (1 + (len(cleartext) % 16))
        target_block = len(cleartext) // 16

        forced_block = block_list(encryption_oracle(known[:offset]))[target_block]
        if forced_block not in lookup:
            print(
                f"!!! did not find block ({target_block}) in lookup (i={i}/{len_unknown}); uncovered = {cleartext}"
            )
        uncovered = lookup[forced_block]
        cleartext += uncovered
        known = bytes(list(known)[1:]) + uncovered

    print("cleartext ->")
    print(cleartext)

    # TODO we get tripped up by the padding inherent in using the full oracle output length as our stopping criteria.
    # Instead, find the size of the secret by feeding progressively longer text into the oracle and looking for the length that makes the output jump by a block size.
