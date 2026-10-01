import pytest

from cryptopals.aes import aes_ecb_encrypt, pkcs7_pad
from cryptopals.analysis import (
    Oracle,
    best_xor_by_column,
    break_ecb_suffix,
    first_repeated_block_index,
    hamming,
    max_repeated_blocks,
    oracle_without_prefix,
    prefix_length,
    random_bytes,
    rank_single_byte_xor,
    unpadded_oracle_secret_length,
)
from cryptopals.xor import single_key_xor

SECRET = b"this is just a random test string"


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


def test_best_columnwise_fails_with_no_texts():
    # empty list of texts
    with pytest.raises(ValueError, match="No texts"):
        best_xor_by_column([])
    # list of empty texts
    with pytest.raises(ValueError, match="No texts"):
        best_xor_by_column([b"", b"", b""])


def test_best_columnwise_fails_unequal_lengths():
    texts = [
        b"one two three four",
        b"five six seven eight",
    ]
    with pytest.raises(ValueError, match="must be equal length"):
        best_xor_by_column(texts)


def columnar_ciphertexts(sample: bytes, key: bytes) -> list[bytes]:
    """
    Rotations of sample, truncated to len(key), each xor'd with key.

    Rows rotate the sample text, so each column is a permutation of the sample
    (which maintains the character frequency), xor'd with one key byte.
    Truncating to len(key) keeps `texts` from being square whenever
    len(key) < len(sample).

    """
    width = len(key)
    rows = [(sample[i:] + sample[:i])[:width] for i in range(len(sample))]
    return [bytes(r ^ k for r, k in zip(row, key, strict=True)) for row in rows]


def test_best_xor_by_column():
    # a fragment of english to start from
    # (which matters because underneath we're scoring on english letter frequency)
    sample = b"It was the best of times, it was the worst of times"
    # an expected key value
    known_key = b"YelLoW suBmarinE"
    texts = columnar_ciphertexts(sample, known_key)

    # best_xor_by_column should return a value matching known_key
    key = best_xor_by_column(texts)
    assert key == known_key


def test_best_xor_by_column_letter_only_is_case_ambiguous():
    # Without spaces or punctuation, k and k ^ 0x20 decrypt each column to the
    # same text up to case, and the scorer lowercases: an exact tie, every column.
    # Only promise the key up to case; which one wins is not part of the contract.
    sample = b"Itwasthebestoftimesitwastheworstoftimes"
    known_key = b"YelLoW suBmarinE"
    texts = columnar_ciphertexts(sample, known_key)

    key = best_xor_by_column(texts)
    for got, k in zip(key, known_key, strict=True):
        assert got in (k, k ^ 0x20)


def test_counting_max_repeated_blocks():
    repeating = b"a" * 32
    nonrepeating = b"a" * 16 + b"b" * 16
    assert max_repeated_blocks(repeating) == 2
    assert max_repeated_blocks(nonrepeating) == 1


def oracle_maker(
    secret: bytes,
    prefix: bytes = b"",
    secret_key: bytes | None = None,
) -> Oracle:
    if secret_key is None:
        secret_key = random_bytes(16)

    def oracle(text: bytes) -> bytes:
        content = prefix + text + secret
        return aes_ecb_encrypt(pkcs7_pad(content), secret_key)

    return oracle


def test_unpadding_oracle():
    full_block = oracle_maker(bytes(16))
    assert unpadded_oracle_secret_length(full_block) == 16

    half_block = oracle_maker(bytes(8))
    assert unpadded_oracle_secret_length(half_block) == 8

    quarter_block = oracle_maker(bytes(4))
    assert unpadded_oracle_secret_length(quarter_block) == 4


def test_first_repeated_block_index():
    repeated = b"A" * 16 * 3
    empty_prefix = pkcs7_pad(b"" + repeated)
    assert first_repeated_block_index(empty_prefix) == 0

    within_first = pkcs7_pad(random_bytes(10) + repeated)
    assert first_repeated_block_index(within_first) == 1

    within_second = pkcs7_pad(random_bytes(19) + repeated)
    assert first_repeated_block_index(within_second) == 2

    nonrepeating = pkcs7_pad(random_bytes(42))
    assert first_repeated_block_index(nonrepeating) is None


@pytest.mark.parametrize("len_prefix", range(43))
def test_prefix_length(len_prefix: int):
    # use deterministic prefix to avoid _value_ confounding measurement of length.
    # (but we can't use a long _repeated_ string, because that's our detection mechanism:
    # a repeated sequence of a given character)
    prefix = bytes(range(len_prefix))
    assert len_prefix == prefix_length(oracle_maker(SECRET, prefix))


# Challenge 14 differs from 12 in that we must negate the impact of a hidden prefix.
# This verifies that we can transform the prefixing oracle into an oracle without one.
@pytest.mark.parametrize("len_prefix", range(43))
def test_removing_oracle_prefix(len_prefix: int):
    secret_key = random_bytes()
    random_prefix = random_bytes(len_prefix)

    # an oracle without a prefix
    unprefixed_oracle = oracle_maker(SECRET, secret_key=secret_key)
    # an oracle with prefix (RANDOM_PREFIX)
    prefixed_oracle = oracle_maker(SECRET, random_prefix, secret_key)

    # an oracle that ignores the prefix
    stripped = oracle_without_prefix(prefixed_oracle, len_prefix)

    plaintext = b"this is the string we control"

    # stripped oracle should match the original no-prefix for a given plaintext
    assert unprefixed_oracle(plaintext) == stripped(plaintext)


# This is the core logic for challenges 12 and 14
#
# We want secrets of lengths between 0..48, to flush
# issues sensitive to block boundaries.
@pytest.mark.parametrize("len_secret", range(49))
def test_break_ecb_suffix(len_secret: int):
    secret = random_bytes(len_secret)
    oracle = oracle_maker(secret)
    result = break_ecb_suffix(oracle)
    assert result == secret
