import random
from enum import Enum
from typing import NamedTuple

from cryptopals.aes import aes_cbc_encrypt, aes_ecb_encrypt, pkcs7_pad
from cryptopals.analysis import max_repeated_blocks, random_bytes


class Mode(Enum):
    ECB = 1
    CBC = 2


class Oracle(NamedTuple):
    mode: Mode
    cipher: bytes


def random_affix() -> bytes:
    return random_bytes(random.randint(5, 10))


def encryption_oracle(plaintext: bytes) -> Oracle:
    plaintext = pkcs7_pad(random_affix() + plaintext + random_affix())
    key = random_bytes(16)
    if random.choice([True, False]):
        return Oracle(Mode.ECB, aes_ecb_encrypt(plaintext, key))
    else:
        iv = random_bytes(16)
        return Oracle(Mode.CBC, aes_cbc_encrypt(plaintext, key, iv))


def discriminator(cipher: bytes) -> Mode:
    dup_blocks = max_repeated_blocks(cipher)
    if dup_blocks > 1:
        return Mode.ECB
    return Mode.CBC


if __name__ == "__main__":
    attack = b"x" * 16 * 3

    # harness to test discriminator
    TRIALS = 1000
    for i in range(TRIALS):
        truth = encryption_oracle(attack)
        guess = discriminator(truth.cipher)
        assert truth.mode == guess, f"{i} -> {guess} does not match true {truth.mode}"

    print(f"Passed n={TRIALS} trials")
