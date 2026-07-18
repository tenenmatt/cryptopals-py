import base64


def from_hex(s: str) -> bytes:
    """Convert a hex string into bytes"""
    return bytes.fromhex(s)


def to_hex(b: bytes) -> str:
    """Render bytes as hex string"""
    return b.hex()


def from_base64(s: str) -> bytes:
    """Convert base64 string into bytes"""
    return base64.b64decode(s)


def to_base64(b: bytes) -> str:
    """Render bytes as base64 string"""
    return base64.b64encode(b).decode("ascii")
