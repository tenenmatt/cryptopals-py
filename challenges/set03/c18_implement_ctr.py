from cryptopals.aes import aes_ctr_cipher
from cryptopals.conversions import from_base64

INPUT = "L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ=="
KEY = b"YELLOW SUBMARINE"
NONCE = bytes(8)

EXPECTED = b"Yo, VIP Let's kick it Ice, Ice, baby Ice, Ice, baby "


if __name__ == "__main__":
    cipher = from_base64(INPUT)
    decoded = aes_ctr_cipher(cipher, KEY, NONCE)
    print(decoded)
    assert decoded == EXPECTED
    # and since CTR is symmetric, we can get the cipher back from what we decoded
    assert aes_ctr_cipher(decoded, KEY, NONCE) == cipher
