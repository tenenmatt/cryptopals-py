from itertools import cycle


def xor(a: bytes, b: bytes) -> bytes:
    """
    Element-wise xor two equal-sized byte sequences

    """
    return bytes(x ^ y for x, y in zip(a, b, strict=True))


def single_key_xor(b: bytes, key: int) -> bytes:
    """xor each element of a byte sequence against the same key"""
    # build rhs to xor with b
    fixed_bytes = bytes([key] * len(b))
    return xor(b, fixed_bytes)


def repeating_xor(b: bytes, key: bytes) -> bytes:
    """
    XOR a byte sequence against a cycling multi-byte key.

    For example, if len(b) is 5, it's XOR with "abcab"
    """
    return bytes(c ^ k for c, k in zip(b, cycle(key)))
