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


def detect_ecb(cipher: bytes) -> float:
    blocks = batched(cipher, 16, strict=True)
    counts = Counter(blocks)
    # return the max repeated blocks, normalized by cipher length
    most_frequent = max(counts.values())
    num_blocks = len(cipher) / 16
    return most_frequent / num_blocks


def pad_block(block: bytes, size: int = 16) -> bytes:
    block_length = len(block)
    if block_length > size:
        raise ValueError("Block is larger than padding target")
    missing = size - block_length
    # PKCS#7 pads with the constant value that's the number of missing bytes
    # eg, if a block is missing 5 bytes, it'd be padded with `b"\05" * 5`
    return block + bytes([missing] * missing)
