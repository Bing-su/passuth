import passuth
from hypothesis import example, given, settings
from hypothesis import strategies as st


@given(text=st.text(max_size=1_000_000))
@example(text="🐍👍")
@example(text="따이タイ泰伊TàiтайتايΤαϊ")
@settings(deadline=500)
def test_generate_hash_str(text: str):
    hash_value = passuth.generate_hash(text)

    assert isinstance(hash_value, str)
    assert passuth.verify_password(text, hash_value)

    text2 = text.encode()
    hash_value2 = passuth.generate_hash(text2)
    assert isinstance(hash_value2, str)
    assert passuth.verify_password(text2, hash_value)


@given(text=st.binary(max_size=1_000_000))
@example(text="🐍👍".encode())
@settings(deadline=500)
def test_generate_hash_bytes(text: bytes):
    hash_value = passuth.generate_hash(text)

    assert isinstance(hash_value, str)
    assert passuth.verify_password(text, hash_value)

    text2 = bytearray(text)
    hash_value2 = passuth.generate_hash(text2)
    assert isinstance(hash_value2, str)
    assert passuth.verify_password(text2, hash_value)


def test_verify_password():
    values = [
        "$argon2i$v=19$m=16,t=2,p=1$ZVZWeGtzNVZqeExTVzNSOA$fx0EYEB1zO8i+J2H+OFI4w",
        "$argon2d$v=19$m=16,t=2,p=1$Mmx3eWR3YkJONkhoTGFnNA$HD1EIj2bqdfwQrJDP+FY6w",
        "$argon2id$v=19$m=16,t=2,p=1$UmtRRmdBRU53QlptNk8ycw$UyyArpJ8yasrc93GImQjFQ",
        "$scrypt$ln=16,r=8,p=1$aM15713r3Xsvxbi31lqr1Q$nFNh2CVHVjNldFVKDHDlm4CbdRSCdEBsjjJxD+iCs5E",
    ]

    for value in values:
        assert passuth.verify_password("password", value)
