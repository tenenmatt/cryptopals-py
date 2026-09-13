from cryptopals.aes import pkcs7_unpad


def assert_success(data, expected):
    assert pkcs7_unpad(data) == expected
    print(f"{data!r} -> {expected!r}")


def assert_failure(data, why):
    try:
        pkcs7_unpad(data)
    except ValueError:
        print(f"{data!r} -> (fail) {why}")
    else:
        raise AssertionError(f"{data!r} should have been rejected!")


if __name__ == "__main__":
    assert_success(b"ICE ICE BABY\x04\x04\x04\x04", b"ICE ICE BABY")

    # Padding bytes hold the wrong value
    assert_failure(b"ICE ICE BABY\x05\x05\x05\x05", "4 padding bytes, but claims 5")
    assert_failure(b"ICE ICE BABY\x01\x02\x03\x04", "padding bytes aren't equal")
