from cryptopals.conversions import from_hex, to_hex
from cryptopals.xor import xor


def solve(input, comparison):
    result = xor(from_hex(input), from_hex(comparison))
    return to_hex(result)


if __name__ == "__main__":
    INPUT = "1c0111001f010100061a024b53535009181c"
    COMPARISON = "686974207468652062756c6c277320657965"
    EXPECTED = "746865206b696420646f6e277420706c6179"

    result = solve(INPUT, COMPARISON)
    assert result == EXPECTED, result
    print(f"xor({INPUT}, {COMPARISON})")
    print(f"-> {result}")
