import pytest
from hypothesis import given
from hypothesis import strategies as st

from cryptopals.conversions import from_base64, from_hex, to_base64, to_hex


@pytest.mark.parametrize(
    "s, expected",
    [
        ("c0 ff e3", b"\xc0\xff\xe3"),
        ("", b""),
    ],
)
def test_from_hex(s, expected):
    assert from_hex(s) == expected


@pytest.mark.parametrize(
    "b, expected",
    [
        (b"\xc0\xff\xe3", "c0ffe3"),
        (b"", ""),
    ],
)
def test_to_hex(b, expected):
    assert to_hex(b) == expected


@given(st.binary())
def test_hex_round_trip(b):
    assert from_hex(to_hex(b)) == b


def test_from_base64():
    assert from_base64("SGVsbG8=") == b"Hello"
    # ignore newline (outside the b64 alphabet),
    # which allows us to split long b64 sequences across lines
    assert from_base64("SGVs\nbG8=") == b"Hello"


def test_to_base64():
    assert to_base64(b"Hello") == "SGVsbG8="


@given(st.binary())
def test_base64_round_trip(b):
    assert from_base64(to_base64(b)) == b
