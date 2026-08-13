import re
from copy import copy, deepcopy

from hypothesis import example, given, settings
from hypothesis import strategies as st
from passuth import Aes128Gcm, Aes128GcmSiv, Aes256Gcm, Aes256GcmSiv, Nonce


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


@given(text=st.text(max_size=1_000_000))
@example(text="🐍👍")
@example(text="따이タイ泰伊TàiтайتايΤαϊ")  # noqa: RUF001
@settings(deadline=1000, max_examples=30)
def test_aes128gcmsiv_encrypt_decrypt_str(text: str):
    aes = Aes128GcmSiv()
    nonce = aes.nonce()
    encrypted = aes.encrypt(nonce, text)
    decrypted = aes.decrypt(nonce, encrypted).decode()

    assert decrypted == text


@given(binary=st.binary(max_size=1_000_000))
@example(binary="🐍👍".encode())
@settings(deadline=1000, max_examples=30)
def test_aes128gcmsiv_encrypt_decrypt_bytes(binary: bytes):
    aes = Aes128GcmSiv()
    nonce = aes.nonce()
    encrypted = aes.encrypt(nonce, binary)
    decrypted = aes.decrypt(nonce, encrypted)

    assert decrypted == binary


@given(text=st.text(max_size=1_000_000))
@example(text="🐍👍")
@example(text="따이タイ泰伊TàiтайتايΤαϊ")  # noqa: RUF001
@settings(deadline=1000, max_examples=30)
def test_aes256gcmsiv_encrypt_decrypt_str(text: str):
    aes = Aes256GcmSiv()
    nonce = aes.nonce()
    encrypted = aes.encrypt(nonce, text)
    decrypted = aes.decrypt(nonce, encrypted).decode()

    assert decrypted == text


@given(binary=st.binary(max_size=1_000_000))
@example(binary="🐍👍".encode())
@settings(deadline=1000, max_examples=30)
def test_aes256gcmsiv_encrypt_decrypt_bytes(binary: bytes):
    aes = Aes256GcmSiv()
    nonce = aes.nonce()
    encrypted = aes.encrypt(nonce, binary)
    decrypted = aes.decrypt(nonce, encrypted)

    assert decrypted == binary


@given(binary=st.binary(min_size=12, max_size=12))
def test_nonce_generation(binary: bytes):
    nonce = Nonce.from_bytes(binary)
    assert bytes(nonce) == binary


def test_nonce_generation2():
    nonce = Nonce.generate()
    assert isinstance(nonce, Nonce)

    b = bytes(nonce)
    nonce2 = Nonce.from_bytes(b)
    assert nonce == nonce2


@given(binary=st.binary(min_size=12, max_size=12))
def test_nonce_hashing(binary: bytes):
    nonce = Nonce.from_bytes(binary)
    hash(nonce)
    mapping = {}
    mapping[nonce] = True
    assert mapping[nonce]


@given(binary=st.binary(min_size=12, max_size=12))
def test_nonce_repr(binary: bytes):
    nonce = Nonce.from_bytes(binary)
    repr_str = repr(nonce)
    assert re.search(r"^Nonce\(hex='[0-9a-fA-F]{24}'\)$", repr_str)


@given(binary=st.binary(min_size=12, max_size=12))
def test_nonce_copy(binary: bytes):
    nonce = Nonce.from_bytes(binary)
    copy1 = copy(nonce)
    copy2 = deepcopy(nonce)
    assert nonce == copy1
    assert nonce == copy2
    assert bytes(nonce) == bytes(copy1)
    assert bytes(nonce) == bytes(copy2)
    assert nonce is not copy1
    assert nonce is not copy2
