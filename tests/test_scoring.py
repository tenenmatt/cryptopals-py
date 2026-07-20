import pytest
from hypothesis import given
from hypothesis import strategies as st

import cryptopals.scoring as sc


def test_identical_cosine_sim():
    x = {b"a": 1, b"b": 2, b"c": 3}
    assert sc.cosine_similarity(x, x) == pytest.approx(1.0)


# strategy for hypothesis testing cosine-sim
nonneg = st.dictionaries(st.binary(min_size=1, max_size=1), st.floats(0.1, 100), min_size=1)


@given(nonneg)
def test_cosine_self_is_one(v):
    assert sc.cosine_similarity(v, v) == pytest.approx(1.0)


@given(nonneg, nonneg)
def test_cosine_is_symmetric(a, b):
    assert sc.cosine_similarity(a, b) == pytest.approx(sc.cosine_similarity(b, a))


def test_disjoint_cosine_sim():
    x = {b"a": 1, b"c": 2}
    y = {b"b": 1, b"d": 2}
    assert sc.cosine_similarity(x, y) == pytest.approx(0.0)


def test_normalize_frequencies():
    freqs = {b"a": 5, b"b": 10, b"c": 15, b"d": 20}
    result = sc.normalize_frequency_table(freqs)
    assert sum(result.values()) == pytest.approx(1.0)


def test_n_gram_parsing():
    # unigrams
    assert sc.n_grams(b"abc") == [b"a", b"b", b"c"]
    assert sc.n_grams(b"") == []
    # bigrams
    assert sc.n_grams(b"foo", n=2) == [b"fo", b"oo"]
    assert sc.n_grams(b"", n=2) == []
    # trigrams
    assert sc.n_grams(b"foo", n=3) == [b"foo"]
    assert sc.n_grams(b"abcd", n=3) == [b"abc", b"bcd"]
    assert sc.n_grams(b"ab", n=3) == []


def test_log_freq_penalizes_garbage():
    correct = b"one two three"
    garbage = b"\x01\x02\x03"
    assert sc.score_log_freqs(correct) > sc.score_log_freqs(garbage)


def test_cosine_penalizes_garbage():
    correct = b"one two three"
    garbage = b"\x01\x02\x03"
    assert sc.score_unigrams(correct) > sc.score_unigrams(garbage)


def test_score_log_freq_handles_empty():
    empty = b""
    not_empty = b"literally anything else"
    assert sc.score_log_freqs(empty) == float("-inf")
    assert sc.score_log_freqs(empty) < sc.score_log_freqs(not_empty)
