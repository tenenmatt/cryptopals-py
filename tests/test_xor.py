import pytest
from hypothesis import given
from hypothesis import strategies as st

from cryptopals.xor import repeating_xor, single_key_xor, xor


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
