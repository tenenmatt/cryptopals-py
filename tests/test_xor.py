import pytest
from hypothesis import given
from hypothesis import strategies as st

from cryptopals.xor import repeating_xor, single_key_xor, truncating_xor, xor, xor_at


@pytest.mark.parametrize(
    "a, b, expected",
    [(b"\x00", b"\x01", b"\x01"), (b"\x01\x01", b"\x01\x00", b"\x00\x01")],
)
def test_xor(a, b, expected):
    assert xor(a, b) == expected


def test_unequal_xor():
    with pytest.raises(ValueError):
        xor(b"\x00", b"\x00\x01")


def test_single_key_xor():
    expected = xor(b"example", b"xxxxxxx")
    observed = single_key_xor(b"example", ord("x"))
    assert observed == expected


def test_repeating_xor():
    expected = xor(b"example", b"abcabca")
    observed = repeating_xor(b"example", b"abc")
    assert observed == expected


@given(st.binary(), st.binary(min_size=1))
def test_repeating_xor_self_inverse(b, key):
    assert repeating_xor(repeating_xor(b, key), key) == b


@given(st.binary(), st.integers(min_value=0, max_value=255))
def test_single_key_xor_self_inverse(b, key):
    assert single_key_xor(single_key_xor(b, key), key) == b


def test_xor_at():
    # docstring example
    assert xor_at(bytes(range(5)), 2, bytes([4, 1])) == bytes([0, 1, 6, 2, 4])
    # single byte
    assert xor_at(bytes(range(5)), 2, bytes([4])) == bytes([0, 1, 6, 3, 4])
    # can't use negative bytes
    with pytest.raises(ValueError):
        xor_at(b"foo", -1, delta=b"bar")
    # delta must fit within text starting at pos
    with pytest.raises(ValueError):
        xor_at(b"foo", 1, delta=b"bar")
    # repeated xor returns original
    repeated = xor_at(xor_at(b"foo", 0, delta=b"bar"), 0, b"bar")
    assert repeated == b"foo"


def test_truncating_xor():
    # same bytes zero out
    assert truncating_xor(b"foo", b"foo") == bytes(3)
    # result is truncated to the length of b
    assert truncating_xor(b"fo", b"foo") == bytes(2)  # NOT 3!
    # key cannot be shorter than b
    with pytest.raises(ValueError):
        truncating_xor(b"foo", b"42")


@given(st.binary(), st.data())
def test_truncating_xor_self_inverse(b, data):
    # fine if the key is longer than the byte sequence (that's what the truncate is for)
    key = data.draw(st.binary(min_size=len(b)))
    assert truncating_xor(truncating_xor(b, key), key) == b


@given(st.binary(), st.data())
def test_truncating_xor_recovers_key(b, data):
    # we lose all information about the key beyond b, so we expect a truncated response
    key = data.draw(st.binary(min_size=len(b)))
    assert truncating_xor(truncating_xor(b, key), b) == key[: len(b)]
