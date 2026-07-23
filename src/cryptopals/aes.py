from itertools import batched, pairwise

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from cryptopals.xor import xor


def aes_ecb_encrypt(text: bytes, key: bytes) -> bytes:
    e = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
    return e.update(text) + e.finalize()


def aes_ecb_decrypt(cipher: bytes, key: bytes) -> bytes:
    d = Cipher(algorithms.AES(key), modes.ECB()).decryptor()
    return d.update(cipher) + d.finalize()


def pad_block(block: bytes, size: int = 16) -> bytes:
    missing = size - (len(block) % size)
    # PKCS#7 pads with the constant value that's the number of missing bytes
    # eg, if a block is missing 5 bytes, it'd be padded with `b"\05" * 5`
    return block + bytes([missing] * missing)


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
