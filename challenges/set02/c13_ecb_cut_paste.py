from cryptopals.aes import aes_ecb_decrypt, aes_ecb_encrypt, pad_block
from cryptopals.analysis import pprint, random_bytes

SECRET_KEY = random_bytes(16)


def parse_structure(text: bytes) -> dict[bytes, bytes]:
    return {k: v for k, v in [it.split(b"=") for it in text.split(b"&")]}


def profile_for(email: str) -> bytes:
    cleaned = email.translate(str.maketrans("", "", "=&"))
    prof = {
        "email": cleaned,
        "uid": 10,  # hard-coding as the simplest starting point
        "role": "user",
    }
    encoded = "&".join(f"{k}={v}" for k, v in prof.items())
    return encoded.encode("ascii")


def encrypt_new_profile(email: str) -> bytes:
    prof = profile_for(email)
    return aes_ecb_encrypt(pad_block(prof), SECRET_KEY)


def decrypt_profile(profile: bytes) -> bytes:
    return aes_ecb_decrypt(profile, SECRET_KEY)


if __name__ == "__main__":
    # need 13-byte email to cause block boundary after "role="
    # (when using fixed "uid=10"!)
    email_forcing_role_cut = "abcde@foo.com"
    # encrypt, and take first 2 blocks (should end after "role=")
    up_to_role = encrypt_new_profile(email_forcing_role_cut)[:32]
    # to fake a new block that's just "admin" and padding (\x0b * 11, because "admin" is 5 bytes),
    # we need to fill the rest of the first block ("email="), so add 10 bogus bytes
    email_forcing_admin = (b"A" * 10 + b"admin" + bytes([11] * 11)).decode("ascii")
    # grab the second block of ciphertext (first block is "email=AAA...", second block is "admin\x0b\x0b...", third block is the other fields)
    admin = encrypt_new_profile(email_forcing_admin)[16:32]
    # Attack: stitch these synthetic blocks together
    compromised = decrypt_profile(up_to_role + admin)
    # we can ignore the last 11 compromised ciphertext bytes--we constructed them to be padding
    prof = parse_structure(compromised[:-11])
    assert prof[b"role"] == b"admin"
    print("Escalated to an admin role!")
    print(prof)
