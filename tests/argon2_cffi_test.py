import passuth
from argon2 import PasswordHasher
from hypothesis import given, settings
from hypothesis import strategies as st


@given(text=st.text(max_size=1000))
@settings(deadline=1000)
def test_argon2_to_passuth(text: str):
    ph = PasswordHasher()
    hash_value = ph.hash(text)
    assert passuth.verify_password(text, hash_value)


@given(text=st.text(max_size=1000))
@settings(deadline=1000)
def test_passuth_to_argon2(text: str):
    ph = PasswordHasher()
    hash_value = passuth.generate_hash(text)
    assert ph.verify(hash_value, text)
