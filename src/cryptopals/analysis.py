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


def best_xor_by_column(texts: list[bytes]) -> bytes:
    """
    Guess the best bytes that xor with columns of a collection of equal-length texts.

    For a result R, R[i] is the byte that produces the best looking distribution
    when xor'd against T[i] for each T in texts (we can think of this as the
    "i-th column" of our texts).

    This will raise when texts are missing or unequal lengths.

    Letter-only columns cannot distinguish k from k ^ 0x20 (the decryptions
    differ only in case); either may be returned.

    """
    if len(texts) == 0 or all(len(t) == 0 for t in texts):
        raise ValueError("No texts to operate on")
    if len(set(len(t) for t in texts)) > 1:
        raise ValueError("Texts must be equal lengths")
    candidate = list()
    # strict=True because we expect texts to be the same length
    cols = [bytes(c) for c in zip(*texts, strict=True)]
    for col in cols:
        # naively choose the highest score with the default scorer for rank_single
        top = rank_single_byte_xor(col)[0]
        candidate.append(top.key)
    return bytes(candidate)


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
    # How many bytes must we inject before the number of blocks change?
    # That tells us how much the padding is adding to
    # the overall length to ensure complete blocks.
    for b in range(16):
        if len(oracle(bytes(b + 1))) > initial_length:
            return initial_length - (b + 1)
    raise ValueError("No change in oracle output. Maybe it isn't padding?")


def oracle_without_prefix(oracle: Oracle, len_prefix: int) -> Oracle:
    """
    Transform an oracle of the form ECB(prefix + plaintext + suffix)
    into one that ignores the prefix, equivalent to ECB(plaintext + suffix).

    This DOES NOT VALIDATE that len_prefix == len(prefix). If that's wrong,
    the resulting oracle will lie!

    Important notes:
    - This assumes 16 byte blocks.
    - The new oracle will modify its plaintext to ensure block alignment
      (necessary to satisfy byte-for-byte equivalence with an unprefixed oracle).

    """
    # be careful not to append a wasted extra block if prefix is already at a boundary
    # (extra `% 16` ensures that we fill 0 rather than 16 when len_prefix is a block multiple)
    fill = (16 - (len_prefix % 16)) % 16
    ignored_bytes = len_prefix + fill

    def trimmed(plaintext: bytes) -> bytes:
        cipher = oracle(b"X" * fill + plaintext)
        return cipher[ignored_bytes:]

    return trimmed


def prefix_length(oracle: Oracle) -> int:
    """
    Determine length of the random prefix prepended by the provided oracle.

    Because we use a repeated-character attack probe to find the edge of the prefix,
    this can be confounded if the prefix happens to have a trailing partial block
    identical to that probe character. That's unlikely with a random prefix, but 256^-(len%16),
    so 1/256 when len(prefix) % 16 = 1.

    This will also break down if the prefix contains at least two identical blocks,
    which will give our edge-detection a false-positive. That's
    exceedingly unlikely, but not impossible.

    Refine, if we run into problems.
    """
    for i in range(16):
        # Using two probes (eg, repeated b"A" and repeated b"B") and checking
        # for agreement would help guard against a prefix with a trailing
        # b"A" block. But we'll have to do something else entirely if the
        # prefix happens to contain two full blocks of any single byte,
        # which would confound first_repeated_block_index.
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
