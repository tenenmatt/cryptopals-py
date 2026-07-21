from collections.abc import Callable
from typing import NamedTuple

from cryptopals.scoring import score_log_freqs
from cryptopals.xor import single_key_xor


class Candidate(NamedTuple):
    key: int
    plaintext: bytes
    score: float


def rank_single_byte_xor(
    cipher: bytes, score: Callable[[bytes], float] = score_log_freqs
) -> list[Candidate]:
    # walrus lets us write this as a one-line generator
    scored = (Candidate(key, pt := single_key_xor(cipher, key), score(pt)) for key in range(256))
    return sorted(scored, key=lambda x: x.score, reverse=True)


def hamming(a: bytes, b: bytes) -> int:
    return sum((ai ^ bi).bit_count() for ai, bi in zip(a, b, strict=True))
