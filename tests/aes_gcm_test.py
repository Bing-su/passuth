from hypothesis import example, given, settings
from hypothesis import strategies as st
from passuth import Aes128Gcm, Aes256Gcm


@given(text=st.text(max_size=1_000_000))
@example(text="🐍👍")
@example(text="따이タイ泰伊TàiтайتايΤαϊ")  # noqa: RUF001
@settings(deadline=1000, max_examples=30)
def test_aes128gcm_encrypt_decrypt_str(text: str):
    aes = Aes128Gcm()
    nonce = aes.nonce()
    encrypted = aes.encrypt(nonce, text)
    decrypted = aes.decrypt(nonce, encrypted).decode()

    assert decrypted == text


@given(binary=st.binary(max_size=1_000_000))
@example(binary="🐍👍".encode())
@settings(deadline=1000, max_examples=30)
def test_aes128gcm_encrypt_decrypt_bytes(binary: bytes):
    aes = Aes128Gcm()
    nonce = aes.nonce()
    encrypted = aes.encrypt(nonce, binary)
    decrypted = aes.decrypt(nonce, encrypted)

    assert decrypted == binary


@given(text=st.text(max_size=1_000_000))
@example(text="🐍👍")
@example(text="따이タイ泰伊TàiтайتايΤαϊ")  # noqa: RUF001
@settings(deadline=1000, max_examples=30)
def test_aes256gcm_encrypt_decrypt_str(text: str):
    aes = Aes256Gcm()
    nonce = aes.nonce()
    encrypted = aes.encrypt(nonce, text)
    decrypted = aes.decrypt(nonce, encrypted).decode()

    assert decrypted == text


@given(binary=st.binary(max_size=1_000_000))
@example(binary="🐍👍".encode())
@settings(deadline=1000, max_examples=30)
def test_aes256gcm_encrypt_decrypt_bytes(binary: bytes):
    aes = Aes256Gcm()
    nonce = aes.nonce()
    encrypted = aes.encrypt(nonce, binary)
    decrypted = aes.decrypt(nonce, encrypted)

    assert decrypted == binary
