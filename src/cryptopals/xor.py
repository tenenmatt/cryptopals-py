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


def cycle(b: bytes):
    length = len(b)
    pos = 0
    while True:
        yield b[pos]
        pos = (pos + 1) % length


def repeating_xor(b: bytes, key: bytes) -> bytes:
    """
    XOR a byte sequence against a cycling multi-byte key.

    For example, if len(b) is 5, it's XOR with "abcab"
    """
    key_cycle = cycle(key)
    key_along = bytes(next(key_cycle) for _ in range(len(b)))
    return xor(b, key_along)
