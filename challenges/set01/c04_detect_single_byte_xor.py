from dataclasses import dataclass
from pathlib import Path

from cryptopals.analysis import rank_single_byte_xor
from cryptopals.conversions import from_hex

DATA_DIR = Path(__file__).resolve().parent.parent / "data"


@dataclass(frozen=True)
class Scored:
    key: bytes
    source: str
    score: float
    text: bytes


def candidates(cipher: str) -> list[Scored]:
    """Return single-byte xor decodings for this cipher"""
    cipher_bytes = from_hex(cipher)
    ranked = rank_single_byte_xor(cipher_bytes)
    return [Scored(bytes([c.key]), cipher, c.score, c.plaintext) for c in ranked]


def solve(data_path: Path) -> list[Scored]:
    all_candidates = []
    for line in data_path.read_text().splitlines():
        # add candidates for this line
        all_candidates += candidates(line)
    # find best scoring across all keys for all lines
    return sorted(all_candidates, key=lambda x: x.score, reverse=True)


if __name__ == "__main__":
    data_path = DATA_DIR / "1.4.txt"
    result = solve(data_path)
    for r in result[:5]:
        print(r)
