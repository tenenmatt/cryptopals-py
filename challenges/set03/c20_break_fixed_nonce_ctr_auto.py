from pathlib import Path

from cryptopals.aes import aes_ctr_cipher
from cryptopals.analysis import Candidate, random_bytes, rank_single_byte_xor
from cryptopals.conversions import from_base64
from cryptopals.xor import repeating_xor

DATA_DIR = Path(__file__).resolve().parent.parent / "data"

KEY = random_bytes(16)
NONCE = bytes(8)


# In this case, data is lines of base64,
# so don't treat as a solid string to decode
def read_data(path: Path) -> list[bytes]:
    raw = path.read_text()
    return [from_base64(line) for line in raw.split()]


def read_challenge_data() -> list[bytes]:
    return read_data(DATA_DIR / "20.txt")


def ciphers() -> list[bytes]:
    secret_plain = read_challenge_data()
    shortest = min(len(ln) for ln in secret_plain)
    truncated = [ln[:shortest] for ln in secret_plain]
    return [aes_ctr_cipher(ln, KEY, NONCE) for ln in truncated]


def best_by_column(texts: list[bytes]) -> bytes:
    candidate = list()
    # strict=True because we expect texts to be the same length, by this point
    cols = [bytes(c) for c in zip(*texts, strict=True)]
    for col in cols:
        # naively choose the highest score for now
        top = rank_single_byte_xor(col)[0]
        candidate.append(top.key)
    return bytes(candidate)


if __name__ == "__main__":
    ciphertexts = ciphers()
    keystream = best_by_column(ciphertexts)
    decoded = [repeating_xor(c, keystream) for c in ciphertexts]
    print("Decoded ciphertext initial segments (truncated to shortest length)")
    for d in decoded:
        print(f"{d!r}")
    # prove that each decoded string matches the plaintext we were given
    # WITH THE EXCEPTION of the first character (scorer ties capitalization in this position)
    for i, given in enumerate(read_challenge_data()):
        assert given[1:53] == decoded[i][1:]
