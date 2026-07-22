from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


def aes_ecb_encrypt(text: bytes, key: bytes) -> bytes:
    e = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
    return e.update(text) + e.finalize()


def aes_ecb_decrypt(cipher: bytes, key: bytes) -> bytes:
    d = Cipher(algorithms.AES(key), modes.ECB()).decryptor()
    return d.update(cipher) + d.finalize()
