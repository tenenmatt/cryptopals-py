from cryptopals.conversions import from_hex, to_base64


def solve(s: str) -> str:
    return to_base64(from_hex(s))


if __name__ == "__main__":
    INPUT = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
    EXPECTED = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"

    result = solve(INPUT)

    assert result == EXPECTED, result
    print(f"hex to base64 ({INPUT})")
    print(f"-> {result}")
