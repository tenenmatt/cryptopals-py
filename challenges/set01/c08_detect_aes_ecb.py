from pathlib import Path
from typing import NamedTuple

from cryptopals.analysis import max_repeated_blocks
from cryptopals.conversions import from_hex

DATA_DIR = Path(__file__).resolve().parent.parent / "data"


class Line(NamedTuple):
    line_num: int
    ciphertext: bytes
    score: float


def read_challenge_data(path: Path) -> list[bytes]:
    return [from_hex(line) for line in path.read_text().splitlines()]


def solve(path: Path) -> Line:
    scores = [
        Line(
            i,
            text,
            max_repeated_blocks(text),
        )
        for i, text in enumerate(read_challenge_data(path))
    ]
    return max(scores, key=lambda x: x.score)


if __name__ == "__main__":
    challenge_file = DATA_DIR / "1.8.txt"

    result = solve(challenge_file)
    print(f"line with most block repetition: {result}")
