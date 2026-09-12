from cryptopals.aes import aes_ecb_encrypt, pkcs7_pad
from cryptopals.analysis import break_ecb_suffix, random_bytes
from cryptopals.conversions import from_base64

SECRET = """
Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg
aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq
dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg
YnkK
"""

# Define this as a global so it's consisent across all invocations
SECRET_KEY = random_bytes(16)


def encryption_oracle(plaintext: bytes) -> bytes:
    plaintext = pkcs7_pad(plaintext + from_base64(SECRET))
    return aes_ecb_encrypt(plaintext, SECRET_KEY)


if __name__ == "__main__":
    result = break_ecb_suffix(encryption_oracle)
    print("cleartext ->")
    print(result)
    assert result == from_base64(SECRET)
