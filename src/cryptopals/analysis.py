import os
import textwrap
from collections import Counter
from collections.abc import Callable
from itertools import batched, pairwise
from typing import NamedTuple

from cryptopals.conversions import to_hex
from cryptopals.scoring import score_log_freqs
from cryptopals.xor import single_key_xor

type Oracle = Callable[[bytes], bytes]


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


def is_ecb(cipher: bytes) -> bool:
    return max_repeated_blocks(cipher) >= 2


def detect_ecb(cipher: bytes) -> float:
    most_frequent = max_repeated_blocks(cipher)
    num_blocks = len(cipher) / 16
    return most_frequent / num_blocks


def first_repeated_block_index(text: bytes) -> int | None:
    blocks = block_list(text)
    for i, (curr, succ) in enumerate(pairwise(blocks)):
        if curr == succ:
            return i
    return None


def random_bytes(n: int = 16) -> bytes:
    return os.urandom(n)


def block_list(text: bytes) -> list[bytes]:
    return list(bytes(x) for x in batched(text, 16, strict=True))


def pprint(text: bytes):
    # print 8 columns (16 bytes)
    width = 8 * 4 + 7
    pretty = textwrap.fill(to_hex(text, True), width)
    print(pretty)


# assumes ECB? also assumes 16-byte block, for now
def unpadded_oracle_secret_length(oracle: Oracle) -> int:
    initial_length = len(oracle(b""))
    for b in range(16):
        if len(oracle(bytes(b + 1))) > initial_length:
            return initial_length - (b + 1)
    raise ValueError("No change in oracle output. Maybe it isn't padding?")


def cut_prefix_oracle(oracle: Oracle, len_prefix: int) -> Oracle:
    """
    Transform an oracle so that it ignores full blocks containing a prefix
    of the specified length.

    """
    # be careful not to append a wasted extra block prefix is already at a boundary
    fill = (16 - (len_prefix % 16)) % 16
    ignored_bytes = len_prefix + fill

    def trimmed(plaintext: bytes) -> bytes:
        cipher = oracle(b"X" * fill + plaintext)
        return cipher[ignored_bytes:]

    return trimmed


def prefix_length(oracle: Oracle) -> int:
    """Determine length of the random prefix prepended by the provided oracle."""
    for i in range(16):
        attack = b"A" * (32 + i)
        repeat = first_repeated_block_index(oracle(attack))
        if repeat is not None:
            return repeat * 16 - i
    raise ValueError("Could not determine prefix length")


def last_byte_lookup_table(oracle: Oracle, known: bytes) -> dict[bytes, bytes]:
    """
    Construct the brute-force table of all possible ciphers when we know
    the first 15 bytes are known but the last byte is unknown.

    """
    lookup = {}
    for b in range(256):
        block = known + bytes([b])
        # get first block of ciphertext
        # TODO assert that len(known) = 15?
        cipher = oracle(block)[:16]
        lookup[cipher] = bytes([b])
    return lookup


# Break initially-padded ECB in challenges 12 and 14
def break_ecb_suffix(oracle: Oracle) -> bytes:
    cleartext = b""
    known = b"A" * 15
    len_unknown = unpadded_oracle_secret_length(oracle)
    for i in range(len_unknown):
        lookup = last_byte_lookup_table(oracle, known)
        offset = 16 - (1 + (len(cleartext) % 16))
        filler = b"A" * offset
        target_block = len(cleartext) // 16

        forced_block = block_list(oracle(filler))[target_block]
        if forced_block not in lookup:
            raise ValueError(
                f"Ciphertext block ({target_block}) matched no candidate "
                f"at byte {i} (of {len_unknown})"
            )
        uncovered = lookup[forced_block]
        # add the newly uncovered byte to our cleartext
        cleartext += uncovered
        # update the most recent 15 uncovered bytes
        known = known[1:] + uncovered
    return cleartext
