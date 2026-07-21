from cryptopals.conversions import to_hex
from cryptopals.xor import repeating_xor


def solve(cleartext: str, key: bytes) -> str:
    # assumes we're always working with ascii
    b = cleartext.encode("ascii")
    cipher = repeating_xor(b, key)
    # expect output as hex string
    return to_hex(cipher)


if __name__ == "__main__":
    INPUT = """Burning 'em, if you ain't quick and nimble
I go crazy when I hear a cymbal"""
    KEY = b"ICE"
    EXPECTED = "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"

    result = solve(INPUT, KEY)
    assert result == EXPECTED, result
    print(f"Success! {result} == {EXPECTED}")
