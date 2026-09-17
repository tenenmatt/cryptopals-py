import base64

import pytest
from hypothesis import given
from hypothesis import strategies as st

from cryptopals.aes import (
    aes_cbc_decrypt,
    aes_cbc_encrypt,
    aes_ctr_cipher,
    aes_ctr_encrypt_counter,
    aes_ctr_keystream,
    aes_ecb_decrypt,
    aes_ecb_encrypt,
    pkcs7_pad,
    pkcs7_unpad,
)

# assumes we're working on full (16 byte) blocks
blocks = st.lists(st.binary(min_size=16, max_size=16)).map(b"".join)
keys = st.binary(min_size=16, max_size=16)
ivs = st.binary(min_size=16, max_size=16)
nonces = st.binary(min_size=8, max_size=8)


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


# Challenge 18 publishes both the ciphertext and (once solved) the plaintext, so
# their XOR is an outside source of truth for the keystream. Decoded with stdlib
# base64 and XORed by hand rather than through the project's own conversions/xor,
# so a bug in those can't mask a bug here.
C18_KEY = b"YELLOW SUBMARINE"
C18_NONCE = bytes(8)
C18_CIPHERTEXT = base64.b64decode(
    "L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ=="
)
C18_PLAINTEXT = b"Yo, VIP Let's kick it Ice, Ice, baby Ice, Ice, baby "


@pytest.mark.parametrize(
    "seq, counter_hex",
    [
        (0, "0000000000000000"),
        (1, "0100000000000000"),  # little-endian: low byte first
        (255, "ff00000000000000"),
        (256, "0001000000000000"),
    ],
)
def test_ctr_counter_block_format(seq, counter_hex):
    """The block fed to AES is nonce || 64-bit *little-endian* seq"""
    key = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    nonce = bytes.fromhex("0011223344556677")
    # AES is invertible, so decrypting the output recovers the counter block itself
    block = aes_ecb_decrypt(aes_ctr_encrypt_counter(key, nonce, seq), key)
    assert block == nonce + bytes.fromhex(counter_hex)


@pytest.mark.parametrize("nonce", [b"", bytes(7), bytes(9), bytes(16), bytes(24)])
def test_ctr_counter_rejects_wrong_nonce_size(nonce):
    # `match` matters: without the guard, AES raises ValueError on its own for most
    # of these (wrong block length) -- and accepts a 24-byte nonce outright. Matching
    # the message is what distinguishes our check from AES's.
    with pytest.raises(ValueError, match="8-byte nonce"):
        aes_ctr_encrypt_counter(bytes(16), nonce, 0)


def test_ctr_keystream_known_answer():
    """Pins the counter format end-to-end against challenge 18's published vector"""
    expected = bytes(p ^ c for p, c in zip(C18_PLAINTEXT, C18_CIPHERTEXT, strict=True))
    keystream = aes_ctr_keystream(C18_KEY, C18_NONCE, len(expected))
    assert keystream[: len(expected)] == expected


@pytest.mark.parametrize(
    "length, expected", [(0, 0), (1, 16), (16, 16), (17, 32), (52, 64), (64, 64)]
)
def test_ctr_keystream_rounds_up_to_block_size(length, expected):
    """Keystream may be longer than `length`, always rounded to the block size"""
    assert len(aes_ctr_keystream(bytes(16), bytes(8), length)) == expected


def test_ctr_cipher_known_answer():
    assert aes_ctr_cipher(C18_CIPHERTEXT, C18_KEY, C18_NONCE) == C18_PLAINTEXT


@given(st.binary(), keys, nonces)
def test_ctr_cipher_is_its_own_inverse(text, key, nonce):
    """Encryption and decryption are the same operation"""
    assert aes_ctr_cipher(aes_ctr_cipher(text, key, nonce), key, nonce) == text


@given(st.binary(), keys, nonces)
def test_ctr_cipher_preserves_length(text, key, nonce):
    """Unlike CBC, no padding: lengths that aren't a multiple of 16 stay exact"""
    assert len(aes_ctr_cipher(text, key, nonce)) == len(text)


@given(st.integers(min_value=0, max_value=64), keys, nonces)
def test_ctr_encrypting_zeros_yields_keystream(length, key, nonce):
    """XOR against zero is the identity, so an oracle handed nulls leaks the keystream"""
    keystream = aes_ctr_keystream(key, nonce, length)
    assert aes_ctr_cipher(bytes(length), key, nonce) == keystream[:length]
