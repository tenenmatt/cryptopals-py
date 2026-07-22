from collections import Counter
from itertools import batched
from pathlib import Path

from cryptopals.conversions import from_hex

DATA_DIR = Path(__file__).resolve().parent.parent / "data"


def read_challenge_data(path: Path) -> list[bytes]:
    return [from_hex(line) for line in path.read_text().splitlines()]


def detect_ecb(cipher: bytes) -> float:
    blocks = batched(cipher, 16, strict=True)
    counts = Counter(blocks)
    # return the max repeated blocks, normalized by cipher length
    most_frequent = max(counts.values())
    num_blocks = len(cipher) / 16
    return most_frequent / num_blocks


def solve(path: Path) -> bytes:
    scores = {line: detect_ecb(line) for line in read_challenge_data(path)}
    key, best_score = max(scores.items(), key=lambda kv: kv[1])
    return key


if __name__ == "__main__":
    challenge_file = DATA_DIR / "1.8.txt"

    result = solve(challenge_file)
    print(f"line with most block repetition: {result}")
