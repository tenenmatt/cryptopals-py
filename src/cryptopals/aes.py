from itertools import batched

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from cryptopals.xor import xor


def aes_ecb_encrypt(text: bytes, key: bytes) -> bytes:
    e = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
    return e.update(text) + e.finalize()


def aes_ecb_decrypt(cipher: bytes, key: bytes) -> bytes:
    d = Cipher(algorithms.AES(key), modes.ECB()).decryptor()
    return d.update(cipher) + d.finalize()


def pkcs7_pad(block: bytes, size: int = 16) -> bytes:
    missing = size - (len(block) % size)
    # PKCS#7 pads with the constant value that's the number of missing bytes
    # eg, if a block is missing 5 bytes, it'd be padded with `b"\05" * 5`
    return block + bytes([missing] * missing)


def pkcs7_unpad(plaintext: bytes, size: int = 16) -> bytes:
    # Plaintext should be nonempty, and complete blocks (multiple of size)
    length = len(plaintext)
    if length == 0 or length % size != 0:
        raise ValueError("Invalid PKCS#7 padding. Partial block")

    # There should be 1..size padding bytes

    pad_size = plaintext[-1]  # last byte will tell us how much padding
    # 0 is never valid, and it's essential to check so we don't plaintext[:-0] (empty)
    if pad_size == 0 or pad_size > size:
        raise ValueError(f"Invalid PKCS#7 padding. {pad_size} is not valid")

    # All padding bytes should be the same value
    padding_bytes = plaintext[-pad_size:]
    if any(b != pad_size for b in padding_bytes):
        raise ValueError(f"Invalid PKCS#7 padding. {padding_bytes} not all {pad_size}")

    # Valid PKCS#7 padding, so return text with padding stripped
    return plaintext[:-pad_size]


def aes_cbc_encrypt(text: bytes, key: bytes, iv: bytes) -> bytes:
    # to start, last_cipher is the initialization vector (IV)
    last_cipher = iv
    ciphertext = b""
    blocks = (bytes(x) for x in batched(text, 16, strict=True))
    for block in blocks:
        # combine prev ciphertext with current
        cbc = xor(last_cipher, block)
        last_cipher = aes_ecb_encrypt(cbc, key)
        ciphertext += last_cipher
    return ciphertext


def aes_cbc_decrypt(text: bytes, key: bytes, iv: bytes) -> bytes:
    last = iv
    cleartext = b""
    blocks = (bytes(x) for x in batched(text, 16, strict=True))
    for block in blocks:
        cleartext += xor(aes_ecb_decrypt(block, key), last)
        last = block
    return cleartext
