from pathlib import Path

from cryptopals.aes import aes_ecb_decrypt
from cryptopals.conversions import from_base64

DATA_DIR = Path(__file__).resolve().parent.parent / "data"


def read_challenge_data(path: Path) -> bytes:
    return from_base64(path.read_text())


def solve(cipher: bytes, key: bytes) -> bytes:
    return aes_ecb_decrypt(cipher, key)


if __name__ == "__main__":
    GIVEN_KEY = b"YELLOW SUBMARINE"

    challenge_file = DATA_DIR / "1.7.txt"
    challenge_data = read_challenge_data(challenge_file)
    result = solve(challenge_data, GIVEN_KEY)

    print(f"Decrypted with key '{GIVEN_KEY}'")
    print(result)
