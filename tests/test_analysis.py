import pytest

from cryptopals.analysis import hamming, pad_block, rank_single_byte_xor
from cryptopals.xor import single_key_xor


def test_recovers_single_byte_key():
    """Make sure that single-byte ranking works given an answer we know up front"""
    secret = b"This is the secret answer"
    key = 0x42
    encrypted = single_key_xor(secret, key)
    # just get the first result, which should be the highest score
    best = rank_single_byte_xor(encrypted)[0]
    assert best.key == key
    assert best.plaintext == secret


def test_ranking_uses_scorer():
    cipher = single_key_xor(b"shhh don't tell", 0x10)
    # target is whatever cleartext 0x42 produces
    target = single_key_xor(cipher, 0x42)

    # provide a scorer than penalizes everything except key 0x42
    def biased(pt: bytes) -> float:
        return 1.0 if pt == target else 0.0

    best = rank_single_byte_xor(cipher, score=biased)[0]
    assert best.key == 0x42


def test_hamming():
    assert hamming(b"this is a test", b"wokka wokka!!!") == 37


def test_padding_default_size():
    short = bytes(14)
    observed = pad_block(short)
    expected = bytes(14) + b"\x02\x02"
    assert observed == expected


def test_padding_full_is_unchanged():
    """If block matches size, don't pad"""
    assert pad_block(bytes(16)) == bytes(16)


def test_padding_block_is_over_size():
    with pytest.raises(ValueError):
        # provided block is bigger than size to pad to
        pad_block(bytes(20), size=16)


@pytest.mark.parametrize(
    "block, size, padding",
    [
        (bytes(16), 20, b"\x04\x04\x04\x04"),
        (bytes(8), 11, b"\x03\x03\x03"),
    ],
)
def test_padding_custom_sizes(block, size, padding):
    assert pad_block(block, size) == block + padding
