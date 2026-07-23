from pathlib import Path

from cryptopals.aes import aes_cbc_decrypt
from cryptopals.conversions import from_base64

DATA_DIR = Path(__file__).resolve().parent.parent / "data"


def read_challenge_data(path: Path) -> bytes:
    return from_base64(path.read_text())


def solve(cipher: bytes, key: bytes) -> bytes:
    zero_block = bytes(16)
    return aes_cbc_decrypt(cipher, key, zero_block)


if __name__ == "__main__":
    GIVEN_KEY = b"YELLOW SUBMARINE"
    CHALLENGE_FILE = DATA_DIR / "10.txt"

    result = solve(read_challenge_data(CHALLENGE_FILE), GIVEN_KEY)

    print(f"Decrypted with key '{GIVEN_KEY}'")
    print(result)
