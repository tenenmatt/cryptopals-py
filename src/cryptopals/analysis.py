import os
from collections import Counter
from collections.abc import Callable
from itertools import batched
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


def max_repeated_blocks(cipher: bytes) -> int:
    blocks = batched(cipher, 16, strict=True)
    counts = Counter(blocks)
    most_frequent = max(counts.values())
    return most_frequent


def detect_ecb(cipher: bytes) -> float:
    most_frequent = max_repeated_blocks(cipher)
    num_blocks = len(cipher) / 16
    return most_frequent / num_blocks


def random_bytes(n: int = 16) -> bytes:
    return os.urandom(n)
