from urllib.parse import quote

from cryptopals.aes import aes_cbc_decrypt, aes_cbc_encrypt, pkcs7_pad
from cryptopals.analysis import random_bytes
from cryptopals.xor import xor, xor_at

SECRET_KEY = random_bytes(16)
IV = random_bytes(16)


def encode_user_data(data: bytes) -> bytes:
    prefix = b"comment1=cooking%20MCs;userdata="
    suffix = b";comment2=%20like%20a%20pound%20of%20bacon"
    # ensure data doesn't have ";" or "=", to keep this nontrivial
    encoded = quote(data).encode()
    return prefix + encoded + suffix


def encrypt_user_data(data: bytes) -> bytes:
    plaintext = encode_user_data(data)
    return aes_cbc_encrypt(pkcs7_pad(plaintext), SECRET_KEY, IV)


def ciphertext_has_admin(ciphertext: bytes) -> bool:
    plaintext = aes_cbc_decrypt(ciphertext, SECRET_KEY, IV)
    return b";admin=true;" in plaintext


def solve() -> bytes:
    """
    We need to manipulate the ciphertext in such a way that we can include ";admin=true;".
    We control the "userdata=" component of the string, but cannot simply include the goal
    string when building up the plaintext (because we encode those special characters).
    But we _can_ seed the plaintext with alternate characters that _aren't_ encoded, and
    then bit-flip the ciphertext to convert those characters to `;` and `=` appropriately.

    Specifically, because CBC xor's the previous cipher block with the current decrypted block,
    we can xor bytes in the previous block with the difference between the initial plaintext
    characters and the desired `;` and `=`, and then CBC machinery will flip the relevant
    bits when decrypting the block containing our goal string, converting our alternates into
    the desired final value.

    """
    # We want a "filler" block before our actual goal string, because the
    # manipulated ciphertext will decrypt to something effectively random.
    attack_seed = b"X" * 16 + b"xadminytruex"
    initial_cipher = encrypt_user_data(attack_seed)
    # Now we need to manipulate bytes the encrypted blocks of our attack_seed
    # to xor(x, ;) and xor(y, =). We can do this bytewise, or we can xor the whole substring
    # and since xor(A, A) = 0 we'll ignore bytes that both strings have in common.
    delta = xor(b"xadminytruex", b";admin=true;")
    # The encode_user_data prefix is exactly two blocks (32 bytes).
    # By construction the first block of our attack_seed is where we'll xor values,
    # so the first of our delta changes should start at index 32.
    attack_cipher = xor_at(initial_cipher, 32, delta)

    # pprint(initial_cipher)
    # pprint(bytes(attack_cipher))

    return bytes(attack_cipher)


if __name__ == "__main__":
    assert not ciphertext_has_admin(encrypt_user_data(b";admin=true;"))
    print("Can't cheat by adding the goal directly")

    attack = solve()

    assert ciphertext_has_admin(attack)
    print("Tampered ciphertext contains admin=true goal")
