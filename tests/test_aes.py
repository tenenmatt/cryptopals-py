import pytest
from hypothesis import given
from hypothesis import strategies as st

from cryptopals.aes import (
    aes_cbc_decrypt,
    aes_cbc_encrypt,
    aes_ecb_decrypt,
    aes_ecb_encrypt,
    pkcs7_pad,
    pkcs7_unpad,
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
    observed = pkcs7_pad(short)
    expected = bytes(14) + b"\x02\x02"
    assert observed == expected


def test_padding_full_produces_extra_block():
    """An input that's already at the block size pads with a full additional block"""
    assert pkcs7_pad(bytes(16)) == bytes(16) + bytes([16] * 16)


@pytest.mark.parametrize(
    "block, size, padding",
    [
        (bytes(16), 20, b"\x04\x04\x04\x04"),
        (bytes(8), 11, b"\x03\x03\x03"),
    ],
)
def test_padding_custom_sizes(block, size, padding):
    assert pkcs7_pad(block, size) == block + padding


# test CBC decrypt(encrypt(x)) == x
@given(blocks, keys, ivs)
def test_cbc_round_trip(text, key, iv):
    assert aes_cbc_decrypt(aes_cbc_encrypt(text, key, iv), key, iv) == text


def test_pkcs7_unpad():
    assert pkcs7_unpad(b"ICE ICE BABY\x04\x04\x04\x04") == b"ICE ICE BABY"
    with pytest.raises(ValueError):
        pkcs7_unpad(b"ICE ICE BABY\x05\x05\x05\x05")
    with pytest.raises(ValueError):
        pkcs7_unpad(b"ICE ICE BABY\x01\x02\x03\x04")
    with pytest.raises(ValueError):
        pkcs7_unpad(b"")
    assert pkcs7_unpad((b"X" * 16) + (b"\x10" * 16)) == b"X" * 16


# We can assert two structural invariants on unpadding:
#
# - unpad(pad(x)) == x — proves it accepts everything it must (no over-rejection)
# - pad(unpad(x)) == x — proves it accepts nothing more, and strips correctly (no over-acceptance)


# First, ensure we accept every correctly-padded plaintext
@given(st.binary())
def test_pkcs7_unpad_removes_padding(text):
    assert pkcs7_unpad(pkcs7_pad(text)) == text


# `pad` is injective -- each message has exactly one valid padded form -- so an
# input is validly padded iff re-padding its stripped body reproduces it byte
# for byte. That makes `pad` the oracle for `unpad`'s accept decision.
#
# Strategy produces two kinds of examples:
# - Two runs of a repeated byte, drawn from a narrow near-legal range
#   (0 and 17 are outside the expected 1..16 padding range), reach wrong
#   pad values, wrong run lengths and wrong alignment from one shape.
# - "Typical" randomly generated plaintext, with a padding byte (in 0..17)
#   repeated 0..20 times. (This is correctly padded iff `pad` agrees with `count`)
pad_values = st.integers(min_value=0, max_value=17)
near_misses = st.builds(
    lambda v1, n1, v2, n2: bytes([v1]) * n1 + bytes([v2]) * n2,
    pad_values,
    st.integers(min_value=0, max_value=34),
    pad_values,
    st.integers(min_value=0, max_value=20),
) | st.builds(
    lambda text, pad, count: text + bytes([pad]) * count,
    st.binary(max_size=34),
    pad_values,
    st.integers(min_value=0, max_value=20),
)


# Use strategy above to ensure we don't accept incorrectly-padded plaintext
@given(near_misses)
def test_pkcs7_unpad_accepts_only_exact_padding(candidate):
    try:
        body = pkcs7_unpad(candidate)
    except ValueError:
        return  # rejected: nothing to prove
    # candidate was validly padded as constructed, so padding
    # the unpadded result should match the original
    assert pkcs7_pad(body) == candidate
