from cryptopals.aes import aes_ecb_decrypt, aes_ecb_encrypt, pad_block
from cryptopals.analysis import random_bytes

SECRET_KEY = random_bytes(16)


def parse_structure(text: bytes) -> dict[bytes, bytes]:
    return {k: v for k, v in [it.split(b"=") for it in text.split(b"&")]}


def profile_for(email: bytes) -> bytes:
    cleaned = email.translate(None, b"=&")
    prof = {
        b"email": cleaned,
        b"uid": b"10",  # hard-coding as the simplest starting point
        b"role": b"user",
    }
    encoded = b"&".join(k + b"=" + v for k, v in prof.items())
    return encoded


def encrypt_new_profile(email: bytes) -> bytes:
    prof = profile_for(email)
    return aes_ecb_encrypt(pad_block(prof), SECRET_KEY)


def decrypt_profile(profile: bytes) -> bytes:
    return aes_ecb_decrypt(profile, SECRET_KEY)


# This blindly trusts the last byte to reflect the padding to strip
# (Real pkcs#7 validation is challenge 15, and then this should migrate to library code)
def naive_strip_padding(cleartext: bytes) -> bytes:
    return cleartext[: -cleartext[-1]]


if __name__ == "__main__":
    # need 13-byte email to cause block boundary after "role="
    # (when using fixed "uid=10"!)
    email_forcing_role_cut = b"abcde@foo.com"
    # encrypt, and take first 2 blocks (should end after "role=")
    up_to_role = encrypt_new_profile(email_forcing_role_cut)[:32]
    # to fake a new block that's just "admin" and padding (\x0b * 11, because "admin" is 5 bytes),
    # we need to fill the rest of the first block ("email="), so add 10 bogus bytes
    email_forcing_admin = b"A" * 10 + b"admin" + b"\x0b" * 11
    # grab the second block of ciphertext (first block is "email=AAA...", second block is "admin\x0b\x0b...", third block is the other fields)
    admin = encrypt_new_profile(email_forcing_admin)[16:32]
    # Attack: stitch these synthetic blocks together
    compromised = decrypt_profile(up_to_role + admin)
    # strip padding before parsing structure
    prof = parse_structure(naive_strip_padding(compromised))
    assert prof[b"role"] == b"admin"
    print("Escalated to an admin role!")
    print(prof)
