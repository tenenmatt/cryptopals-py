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


def xor_at(text: bytes, pos: int, delta: bytes) -> bytes:
    """
    Given a byte sequence, XOR the bytes starting at pos with delta.

    For example:
        xor_at(bytes(range(5)), 2, bytes([4, 1])) -> b"\x00\x01\x06\x02\x04"
    changes the 2 at position 2 to a 6 (xor(2, 4)) and the 3 to 2 (xor(3, 1))

    Change a single byte by calling with a list of one item,
    like `delta=bytes([42])`
    """
    if pos < 0 or pos + len(delta) > len(text):
        raise ValueError(f"xor_at: [{pos}, {pos + len(delta)}) out of range for length {len(text)}")
    changed = bytearray(text)
    for i, d in enumerate(delta):
        changed[pos + i] ^= d
    return bytes(changed)


def truncating_xor(b: bytes, key: bytes) -> bytes:
    """
    XOR byte sequence against a key, possibly truncating the key if it's longer than the sequence
    (as in the case of CTR keystream)

    """
    if len(b) > len(key):
        raise ValueError(f"Key string is not long enough ({len(key)}, expected at least {len(b)})")
    return xor(b, key[: len(b)])
