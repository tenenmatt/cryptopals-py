from dataclasses import dataclass
from itertools import batched, islice, pairwise
from pathlib import Path

from cryptopals.analysis import best_xor_by_column, hamming, rank_single_byte_xor
from cryptopals.conversions import from_base64
from cryptopals.scoring import score_log_freqs
from cryptopals.xor import repeating_xor

DATA_DIR = Path(__file__).resolve().parent.parent / "data"


@dataclass(frozen=True)
class Decoded:
    key: bytes
    score: float
    text: bytes


@dataclass(frozen=True)
class EstimatedKeySize:
    size: int
    distance: float


def read_challenge_data(path: Path) -> bytes:
    return from_base64(path.read_text())


def estimate_key_size(
    cipher: bytes, top: int = 3, min_size: int = 2, max_size: int = 40, samples: int = 4
) -> list[int]:
    candidates = []
    for n in range(min_size, max_size):
        # get the first few chunks of size n (count controlled by `samples` arg)
        grouped = (bytes(x) for x in batched(cipher, n, strict=False))
        chunks = list(islice(grouped, 0, samples))

        distances = [hamming(pair[0], pair[1]) / n for pair in pairwise(chunks)]
        avg_distance = sum(distances) / len(distances)
        candidates.append(EstimatedKeySize(n, avg_distance))
    best = sorted(candidates, key=lambda x: x.distance)[:top]
    return [x.size for x in best]


def solve(cipher: bytes) -> list[Decoded]:
    key_sizes = estimate_key_size(cipher, max_size=40)
    print(f"key_sizes = {key_sizes}")
    results = []
    for size in key_sizes:
        # break into size chunks, transpose, solve each column, combine top keys
        # (exclude short chunks, which break the transposition)
        chunks = [bytes(x) for x in batched(cipher, size, strict=False) if len(x) == size]
        key = best_xor_by_column(chunks)
        print(f"try key {key} ({size})")
        # try this key on full ciphertext
        cleartext = repeating_xor(cipher, key)
        results.append(Decoded(key, score_log_freqs(cleartext), cleartext))
    return sorted(results, key=lambda x: x.score, reverse=True)


if __name__ == "__main__":
    challenge_file = DATA_DIR / "1.6.txt"
    challenge_data = read_challenge_data(challenge_file)
    result = solve(challenge_data)

    for r in result[:1]:
        print(f"Key = {r.key} (score: {r.score}")
        print(r.text)
