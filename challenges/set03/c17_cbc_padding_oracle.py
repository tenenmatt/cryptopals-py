from itertools import batched, pairwise
from random import choice

from cryptopals.aes import aes_cbc_decrypt, aes_cbc_encrypt, pkcs7_pad, pkcs7_unpad
from cryptopals.analysis import pprint, random_bytes
from cryptopals.conversions import from_base64

SECRET_KEY = random_bytes()

CANDIDATE_PLAINTEXTS = [
    "MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=",
    "MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=",
    "MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==",
    "MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==",
    "MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl",
    "MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==",
    "MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==",
    "MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=",
    "MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=",
    "MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93",
]


# because we manage a secret key internally, expose core encryption and decryption
# for easier exploration and testing
def encrypt(plain: bytes, iv: bytes) -> bytes:
    return aes_cbc_encrypt(pkcs7_pad(plain), SECRET_KEY, iv)


def decrypt(cipher: bytes, iv: bytes) -> bytes:
    return aes_cbc_decrypt(cipher, SECRET_KEY, iv)


def choose_cipher() -> tuple[bytes, bytes]:
    iv = random_bytes()
    # choose a candidate (not random yet, while testing a little)
    plaintext = from_base64(choice(CANDIDATE_PLAINTEXTS))
    return encrypt(plaintext, iv), iv


def is_valid_padding(plaintext: bytes) -> bool:
    try:
        pkcs7_unpad(plaintext)
    except ValueError:
        return False
    else:
        return True


def padding_oracle(cipher: bytes, iv: bytes) -> bool:
    decrypted = decrypt(cipher, iv)
    return is_valid_padding(decrypted)


def xor_byte(text: bytes, pos: int, value: int) -> bytes:
    """
    Given a byte sequence, xor the byte at pos with value.

    For example:
        xor_byte(bytes(range(5)), 2, 4) -> b"\x00\x01\x06\x03\x04"
    changes the 2 at position 2 to a 6 (xor(2, 4))
    """
    changed = bytearray(text)
    changed[pos] ^= value
    return bytes(changed)


# Only ever one valid padding outcome (possible false-positives in the terminal position, which we need to check against)
def block_mask_pos(block: bytes, previous: bytes, pos: int) -> int:
    assert pos < len(block)
    for atk in range(256):
        tampered = xor_byte(previous, pos, atk)
        if padding_oracle(block, tampered):
            # for byte at the end of the block, we only know that it's valid padding, _not_ that
            # it's been tampered to 0x01. Check the adjacent byte. If tampering
            # still passes the padding validation, we have 0x01 in terminal position;
            # otherwise, it was a false positive.
            if pos + 1 == len(block):
                tampered = xor_byte(tampered, pos - 1, 1)
                if padding_oracle(block, tampered):
                    return atk
            else:
                return atk
    raise ValueError(f"Could not force a padding hit at P[{pos}]")


def decode_block(block: bytes, previous: bytes):
    len_block = len(block)
    decoded = bytearray(len_block)
    # start at the end and work toward the beginning
    tampered = bytearray(previous)
    for i in reversed(range(len_block)):
        mask = block_mask_pos(block, bytes(tampered), i)
        padding_target = len_block - i
        clear = mask ^ padding_target
        # print(f"P[{i}] = {mask} ^ {padding_target} = {chr(clear)}")
        decoded[i] = clear
        # now update tampered to set rightward bytes to padding_target+1 for next iteration
        for r in range(i, len_block):
            # setting tampered[r] to `previous[r] ^ decoded[r]` means that
            # when we xor it with the (hidden) cleartext bit we get 0x00
            # (previous[r] ^ clear[r] -> decoded[r], so
            # previous[r] ^ decoded[r] ^ clear[r] -> decoded[r] ^ decoded[r])
            #
            # that means we can set the effective cleartext to whatever we
            # want by appending an xor with the desired value
            tampered[r] = previous[r] ^ decoded[r] ^ (padding_target + 1)
    return bytes(decoded)


def solve(cipher: bytes, iv: bytes) -> bytes:
    cleartext = bytearray()
    for prev, block in pairwise(batched(iv + cipher, 16, strict=True)):
        cleartext += decode_block(bytes(block), bytes(prev))
    return pkcs7_unpad(bytes(cleartext))


if __name__ == "__main__":
    cipher, iv = choose_cipher()
    decoded = solve(cipher, iv)
    # assert that what we decoded was among the (hidden) cleartext options
    assert decoded in [from_base64(cand) for cand in CANDIDATE_PLAINTEXTS]
    print(f"PASS Cleartext was among the candidates: {decoded!r}")
