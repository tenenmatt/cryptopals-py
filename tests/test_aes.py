import pytest
from hypothesis import given
from hypothesis import strategies as st

from cryptopals.aes import (
    aes_cbc_decrypt,
    aes_cbc_encrypt,
    aes_ecb_decrypt,
    aes_ecb_encrypt,
    pad_block,
)

# assumes we're working on full (16 byte) blocks
blocks = st.lists(st.binary(min_size=16, max_size=16)).map(b"".join)
keys = st.binary(min_size=16, max_size=16)
ivs = st.binary(min_size=16, max_size=16)


# test that decrypt(encrypt(x)) == x
@given(blocks, keys)
def test_ecb_round_trip(text, key):
    assert aes_ecb_decrypt(aes_ecb_encrypt(text, key), key) == text


def test_ecb_known_answer():
    key = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    cleartext = bytes.fromhex("00112233445566778899aabbccddeeff")
    ciphertext = bytes.fromhex("69c4e0d86a7b0430d8cdb78070b4c55a")
    assert aes_ecb_encrypt(cleartext, key) == ciphertext  # pins the algorithm, both directions
    assert aes_ecb_decrypt(ciphertext, key) == cleartext


def test_ecb_blocks_are_deterministic():
    """Identical text blocks produce identical ciphertext"""
    key = bytes(16)
    # two copies of a block [0..15]
    cipher = aes_ecb_encrypt(bytes(range(16)) * 2, key)
    assert cipher[:16] == cipher[16:]


def test_padding_default_size():
    short = bytes(14)
    observed = pad_block(short)
    expected = bytes(14) + b"\x02\x02"
    assert observed == expected


def test_padding_full_produces_extra_block():
    """An input that's already at the block size pads with a full additional block"""
    assert pad_block(bytes(16)) == bytes(16) + bytes([16] * 16)


@pytest.mark.parametrize(
    "block, size, padding",
    [
        (bytes(16), 20, b"\x04\x04\x04\x04"),
        (bytes(8), 11, b"\x03\x03\x03"),
    ],
)
def test_padding_custom_sizes(block, size, padding):
    assert pad_block(block, size) == block + padding


# test CBC decrypt(encrypt(x)) == x
@given(blocks, keys, ivs)
def test_cbc_round_trip(text, key, iv):
    assert aes_cbc_decrypt(aes_cbc_encrypt(text, key, iv), key, iv) == text
