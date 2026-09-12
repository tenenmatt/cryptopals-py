from cryptopals.aes import pkcs7_pad


def solve(block: bytes, size: int):
    return pkcs7_pad(block, size)


if __name__ == "__main__":
    EXAMPLE_TEXT = b"YELLOW SUBMARINE"
    BLOCK_SIZE = 20

    result = solve(EXAMPLE_TEXT, BLOCK_SIZE)
    print(f"pad({EXAMPLE_TEXT}) = {result}")
