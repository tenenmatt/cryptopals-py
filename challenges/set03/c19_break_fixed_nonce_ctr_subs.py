import math

from cryptopals.aes import aes_ctr_cipher
from cryptopals.analysis import Candidate, random_bytes, rank_single_byte_xor
from cryptopals.conversions import from_base64
from cryptopals.xor import xor

KEY = random_bytes(16)
NONCE = bytes(8)

RAW_INPUT = """
SSBoYXZlIG1ldCB0aGVtIGF0IGNsb3NlIG9mIGRheQ==
Q29taW5nIHdpdGggdml2aWQgZmFjZXM=
RnJvbSBjb3VudGVyIG9yIGRlc2sgYW1vbmcgZ3JleQ==
RWlnaHRlZW50aC1jZW50dXJ5IGhvdXNlcy4=
SSBoYXZlIHBhc3NlZCB3aXRoIGEgbm9kIG9mIHRoZSBoZWFk
T3IgcG9saXRlIG1lYW5pbmdsZXNzIHdvcmRzLA==
T3IgaGF2ZSBsaW5nZXJlZCBhd2hpbGUgYW5kIHNhaWQ=
UG9saXRlIG1lYW5pbmdsZXNzIHdvcmRzLA==
QW5kIHRob3VnaHQgYmVmb3JlIEkgaGFkIGRvbmU=
T2YgYSBtb2NraW5nIHRhbGUgb3IgYSBnaWJl
VG8gcGxlYXNlIGEgY29tcGFuaW9u
QXJvdW5kIHRoZSBmaXJlIGF0IHRoZSBjbHViLA==
QmVpbmcgY2VydGFpbiB0aGF0IHRoZXkgYW5kIEk=
QnV0IGxpdmVkIHdoZXJlIG1vdGxleSBpcyB3b3JuOg==
QWxsIGNoYW5nZWQsIGNoYW5nZWQgdXR0ZXJseTo=
QSB0ZXJyaWJsZSBiZWF1dHkgaXMgYm9ybi4=
VGhhdCB3b21hbidzIGRheXMgd2VyZSBzcGVudA==
SW4gaWdub3JhbnQgZ29vZCB3aWxsLA==
SGVyIG5pZ2h0cyBpbiBhcmd1bWVudA==
VW50aWwgaGVyIHZvaWNlIGdyZXcgc2hyaWxsLg==
V2hhdCB2b2ljZSBtb3JlIHN3ZWV0IHRoYW4gaGVycw==
V2hlbiB5b3VuZyBhbmQgYmVhdXRpZnVsLA==
U2hlIHJvZGUgdG8gaGFycmllcnM/
VGhpcyBtYW4gaGFkIGtlcHQgYSBzY2hvb2w=
QW5kIHJvZGUgb3VyIHdpbmdlZCBob3JzZS4=
VGhpcyBvdGhlciBoaXMgaGVscGVyIGFuZCBmcmllbmQ=
V2FzIGNvbWluZyBpbnRvIGhpcyBmb3JjZTs=
SGUgbWlnaHQgaGF2ZSB3b24gZmFtZSBpbiB0aGUgZW5kLA==
U28gc2Vuc2l0aXZlIGhpcyBuYXR1cmUgc2VlbWVkLA==
U28gZGFyaW5nIGFuZCBzd2VldCBoaXMgdGhvdWdodC4=
VGhpcyBvdGhlciBtYW4gSSBoYWQgZHJlYW1lZA==
QSBkcnVua2VuLCB2YWluLWdsb3Jpb3VzIGxvdXQu
SGUgaGFkIGRvbmUgbW9zdCBiaXR0ZXIgd3Jvbmc=
VG8gc29tZSB3aG8gYXJlIG5lYXIgbXkgaGVhcnQs
WWV0IEkgbnVtYmVyIGhpbSBpbiB0aGUgc29uZzs=
SGUsIHRvbywgaGFzIHJlc2lnbmVkIGhpcyBwYXJ0
SW4gdGhlIGNhc3VhbCBjb21lZHk7
SGUsIHRvbywgaGFzIGJlZW4gY2hhbmdlZCBpbiBoaXMgdHVybiw=
VHJhbnNmb3JtZWQgdXR0ZXJseTo=
QSB0ZXJyaWJsZSBiZWF1dHkgaXMgYm9ybi4=
"""


def ciphers() -> list[bytes]:
    return [aes_ctr_cipher(from_base64(b), KEY, NONCE) for b in RAW_INPUT.strip().splitlines()]


CIPHERTEXTS = ciphers()


def score_column(col: int, cutoff: float = -math.inf) -> list:
    column = bytes(c[col] for c in CIPHERTEXTS if len(c) > col)
    scores = rank_single_byte_xor(column)
    if len(column) < len(CIPHERTEXTS):
        print(f"Skipped {len(CIPHERTEXTS) - len(column)}/{len(CIPHERTEXTS)} short lines")
    # log-normal scores are negative, so cutoff bounds from below
    return [s for s in scores if s.score >= cutoff]


# may not need this beyond exploration
def xor_ciphers(keystream: bytes) -> list[bytes]:
    def xor(c: bytes) -> bytes:
        return bytes([ci ^ ki for ci, ki in zip(c, keystream, strict=False)])

    return [xor(c) for c in CIPHERTEXTS]


# print for debug/exploration
def print_decoded(lim=None):
    texts = xor_ciphers(bytes(KEYSTREAM))
    if lim is None:
        lim = len(texts)
    for t in texts[:lim]:
        print(f"{t!r}")


def print_scores(scores: list[Candidate]):
    for s in scores:
        print(f"{s}")


KEYSTREAM = bytearray(max(len(c) for c in CIPHERTEXTS))
# 0x00 is a legitimate keystream byte, so zeroed KEYSTREAM slots can't mean "unset"
KNOWN: set[int] = set()


def set_key_byte(i: int, value: int):
    KEYSTREAM[i] = value
    KNOWN.add(i)


def clear_key_bytes(start: int, stop: int | None = None) -> None:
    """Retract committed keystream bytes in [start, stop) so they can be re-guessed."""
    if stop is None:
        stop = len(KEYSTREAM)
    for i in range(start, stop):
        KNOWN.discard(i)
        KEYSTREAM[i] = 0


def set_key_bytes(line: int, guess: bytes, start: int = 0) -> None:
    """Commit a guessed plaintext for CIPHERTEXTS[line], deriving K = P ^ C."""
    cipher = CIPHERTEXTS[line][start : start + len(guess)]
    if len(cipher) < len(guess):
        raise ValueError(
            f"line {line} has {len(CIPHERTEXTS[line]) - start} bytes from {start}, "
            f"guess needs {len(guess)}"
        )
    for offset, k in enumerate(xor(guess, cipher), start=start):
        if offset in KNOWN and KEYSTREAM[offset] != k:
            raise ValueError(
                f"byte {offset}: guess implies {k:#04x}, already committed {KEYSTREAM[offset]:#04x}"
            )
        set_key_byte(offset, k)


if __name__ == "__main__":
    # This challenge is inherently interactive, because the column-wise
    # substitution evaluation depends on human judgment. In general, it
    # looks like:
    # print_scores(score_column(0, -3)) # eg, candidates for first column
    # set_key_byte(0, 154) # set keystream[0] to the right-looking score (often but not always the first)
    # print_decoded() # evaluate progress across lines

    # This is the longest line with any overlap, which leaves only a
    # couple characters dangling in CIPHERTEXTS[37] (but they're
    # genuinely encrypted--there's nothing to compromise a one-time pad
    # without overlap)
    #
    # The liberal arts major in me would guess that long line is
    # "He, too, has been changed in his turn,"
    set_key_bytes(4, b"I have passed with a nod of the head")
    print_decoded()
