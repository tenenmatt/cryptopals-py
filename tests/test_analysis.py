import pytest

from cryptopals.analysis import hamming, rank_single_byte_xor
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
