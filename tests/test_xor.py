import pytest

from cryptopals.xor import xor


@pytest.mark.parametrize(
    "a, b, expected",
    [(b"\x00", b"\x01", b"\x01"), (b"\x01\x01", b"\x01\x00", b"\x00\x01")],
)
def test_xor(a, b, expected):
    assert xor(a, b) == expected


def test_unequal_xor():
    with pytest.raises(ValueError):
        xor(b"\x00", b"\x00\x01")
