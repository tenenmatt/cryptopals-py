from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


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


