from collections import Counter
from collections.abc import Mapping
import math


def normalize_frequency_table(freqs: Mapping[bytes, float]) -> Mapping[bytes, float]:
    total = sum(freqs.values())
    return {k: v / total for k, v in freqs.items()}


# https://pi.math.cornell.edu/~mec/2003-2004/cryptography/subs/frequencies.html
COMMON_LETTER_FREQUENCIES = normalize_frequency_table(
    {
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
)

COMMON_BIGRAM_FREQUENCIES = normalize_frequency_table(
    {
        b"th": 0.0356,
        b"he": 0.0307,
        b"in": 0.0243,
        b"er": 0.0205,
        b"an": 0.0199,
        b"re": 0.0185,
        b"on": 0.0176,
        b"at": 0.0149,
        b"en": 0.0145,
        b"nd": 0.0135,
        b"ti": 0.0134,
        b"es": 0.0134,
        b"or": 0.0128,
        b"te": 0.0120,
        b"of": 0.0117,
        b"ed": 0.0117,
        b"is": 0.0113,
        b"it": 0.0112,
        b"al": 0.0109,
        b"ar": 0.0107,
        b"st": 0.0105,
        b"to": 0.0105,
        b"nt": 0.0104,
        b"ng": 0.0095,
        b"se": 0.0093,
        b"ha": 0.0093,
        b"as": 0.0087,
        b"ou": 0.0087,
        b"io": 0.0083,
        b"le": 0.0083,
        b"ve": 0.0083,
        b"co": 0.0079,
        b"me": 0.0079,
        b"de": 0.0076,
        b"hi": 0.0076,
        b"ri": 0.0073,
        b"ro": 0.0073,
        b"ic": 0.0070,
        b"ne": 0.0069,
        b"ea": 0.0069,
        b"ra": 0.0069,
        b"ce": 0.0065,
    }
)


def n_grams(text: bytes, n: int = 1) -> list[bytes]:
    return [text[i : i + n] for i in range(len(text) - n + 1)]


def count_frequencies(
    text: bytes, n: int = 1, freq_ref: Mapping[bytes, float] = COMMON_LETTER_FREQUENCIES
) -> dict[bytes, int]:
    """Count n-gram frequencies in text"""
    # consolidate case, since frequencies are lowercase
    # (assumes text is ascii)
    lower_text = text.lower()
    freqs = Counter()
    # only count values in reference frequencies
    # (this will work generically now, if we parametrize the frequencies)
    for gram in n_grams(lower_text, n):
        if gram in freq_ref:
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


def score_ngrams(
    text: bytes, n: int = 1, freq_ref: Mapping[bytes, float] = COMMON_LETTER_FREQUENCIES
) -> float:
    freq = count_frequencies(text, n, freq_ref)
    return cosine_similarity(freq, freq_ref)


# could use functools.partial for these wrappers around score_ngrams?
def score_bigrams(text: bytes) -> float:
    return score_ngrams(text, n=2, freq_ref=COMMON_BIGRAM_FREQUENCIES)


def score_unigrams(text: bytes) -> float:
    return score_ngrams(text)


def score_log_freqs(
    text: bytes,
    n: int = 1,
    freq_ref: Mapping[bytes, float] = COMMON_LETTER_FREQUENCIES,
) -> float:
    lower_text = text.lower()
    score = 0
    num_grams = 0  # for normalizing length
    missing_freq = min(freq_ref.values()) / 2
    for gram in n_grams(lower_text, n):
        freq = freq_ref.get(gram, missing_freq)
        num_grams += 1
        score += math.log(freq)
    if num_grams == 0:
        return float("-inf")
    return score / num_grams
