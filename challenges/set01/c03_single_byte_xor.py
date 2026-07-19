from dataclasses import dataclass
from cryptopals.xor import xor
from cryptopals.conversions import from_hex
from cryptopals.scoring import score_unigrams


@dataclass(frozen=True)
class Scored:
    key: bytes
    score: float
    text: bytes


def single_key_xor(b: bytes, key: int) -> bytes:
    # build rhs to xor with b
    fixed_bytes = bytes([key] * len(b))
    return xor(b, fixed_bytes)


def score(text: bytes) -> float:
    return score_unigrams(text)


def solve(cipher: str) -> list[Scored]:
    cipher_bytes = from_hex(cipher)
    candidates = []
    # test every possible single-byte key
    for key in range(256):
        cleartext = single_key_xor(cipher_bytes, key)
        # coerce key back to byte literal
        candidates.append(Scored(key=bytes([key]), score=score(cleartext), text=cleartext))
    return sorted(candidates, key=lambda x: x.score, reverse=True)


if __name__ == "__main__":
    CIPHER = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"

    result = solve(CIPHER)

    for r in result[:5]:
        print(r)
