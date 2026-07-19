from collections import Counter
from collections.abc import Mapping
import math


# https://pi.math.cornell.edu/~mec/2003-2004/cryptography/subs/frequencies.html
COMMON_LETTER_FREQUENCIES = {
    b"e": 12.02,
    b"t": 9.10,
    b"a": 8.12,
    b"o": 7.68,
    b"i": 7.31,
    b"n": 6.95,
    b"s": 6.28,
    b"r": 6.02,
    b"h": 5.92,
    b"d": 4.32,
    b"l": 3.98,
    b"u": 2.88,
    b"c": 2.71,
    b"m": 2.61,
    b"f": 2.30,
    b"y": 2.11,
    b"w": 2.09,
    b"g": 2.03,
    b"p": 1.82,
    b"b": 1.49,
    b"v": 1.11,
    b"k": 0.69,
    b"x": 0.17,
    b"q": 0.11,
    b"j": 0.10,
    b"z": 0.07,
    # add space to weed out gibberish with coincidental frequent chars
    b" ": 10.0,  # 10 is arbitrary, but needs to be close to highest value to help
}


def n_grams(text: bytes, n: int = 1) -> list[bytes]:
    return [text[i : i + n] for i in range(len(text) - n + 1)]


def count_letter_frequencies(text: bytes) -> dict[bytes, int]:
    # consolidate case, since frequencies are lowercase
    # (assumes text is ascii)
    lower_text = text.lower()
    freqs = Counter()
    # only count values in reference frequencies
    # (this will work generically now, if we parametrize the frequencies)
    for gram in n_grams(lower_text):
        if gram in COMMON_LETTER_FREQUENCIES:
            freqs[gram] += 1
    return freqs


def cosine_similarity(a: Mapping[bytes, float], b: Mapping[bytes, float]) -> float:
    dot = 0
    a_mag, b_mag = 0, 0
    for k in a.keys() | b.keys():
        av, bv = a.get(k, 0), b.get(k, 0)
        dot += av * bv
        a_mag += av * av
        b_mag += bv * bv
    if a_mag == 0 or b_mag == 0:
        return 0
    return dot / (math.sqrt(a_mag) * math.sqrt(b_mag))


def score_unigrams(text: bytes) -> float:
    # make this generic for n-grams by changing count_letter_frequencies
    # to take an n-gram size and the corresponding reference freqs
    # (which can then also be passed to cosine similarity)
    freq = count_letter_frequencies(text)
    return cosine_similarity(freq, COMMON_LETTER_FREQUENCIES)
