from dataclasses import dataclass
from pathlib import Path

from cryptopals.conversions import from_hex
from cryptopals.scoring import score_log_freqs
from cryptopals.xor import single_key_xor

DATA_DIR = Path(__file__).resolve().parent.parent / "data"


@dataclass(frozen=True)
class Scored:
    key: bytes
    source: str
    score: float
    text: bytes


def score(text: bytes) -> float:
    return score_log_freqs(text)


def candidates(cipher: str) -> list[Scored]:
    """Return single-byte xor decodings for this cipher"""
    cipher_bytes = from_hex(cipher)
    results = []
    for key in range(256):
        cleartext = single_key_xor(cipher_bytes, key)
        # coerce back to byte literal for Scored.key
        results.append(
            Scored(key=bytes([key]), source=cipher, score=score(cleartext), text=cleartext)
        )
    return results


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
