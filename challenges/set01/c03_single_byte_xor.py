from dataclasses import dataclass

from cryptopals.analysis import rank_single_byte_xor
from cryptopals.conversions import from_hex


@dataclass(frozen=True)
class Scored:
    key: bytes
    score: float
    text: bytes


def solve(cipher: str) -> list[Scored]:
    cipher_bytes = from_hex(cipher)
    candidates = rank_single_byte_xor(cipher_bytes)
    # translate results into Scored
    return [Scored(bytes([c.key]), c.score, c.plaintext) for c in candidates]


if __name__ == "__main__":
    CIPHER = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"

    result = solve(CIPHER)

    for r in result[:5]:
        print(r)
