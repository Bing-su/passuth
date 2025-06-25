import copy
import pickle

import jsonpickle
from hypothesis import given
from hypothesis import strategies as st
from passuth import Fernet

TXT = "Hello, World!"


@given(text=st.text(max_size=1_000_000))
def test_fernet_encrypt_decrypt(text: str):
    fernet = Fernet(Fernet.generate_key())
    encrypted = fernet.encrypt(text)
    decrypted = fernet.decrypt(encrypted).decode()

    assert decrypted == text


@given(binary=st.binary(max_size=1_000_000))
def test_fernet_encrypt_decrypt_bytes(binary: bytes):
    fernet = Fernet.new()
    encrypted = fernet.encrypt(binary)
    decrypted = fernet.decrypt(encrypted)

    assert decrypted == binary


def test_fernet_pickle():
    fernet = Fernet(Fernet.generate_key())
    encrypted = fernet.encrypt(TXT)

    pickled_fernet = pickle.dumps(fernet)
    unpickled_fernet = pickle.loads(pickled_fernet)  # noqa: S301

    decrypted = unpickled_fernet.decrypt(encrypted).decode()

    assert decrypted == TXT


def test_fernet_jsonpickle():
    fernet = Fernet.new()
    encrypted = fernet.encrypt(TXT)

    pickled_fernet = jsonpickle.dumps(fernet)
    unpickled_fernet: Fernet = jsonpickle.loads(pickled_fernet)  # pyright: ignore[reportAssignmentType]

    decrypted = unpickled_fernet.decrypt(encrypted).decode()

    assert decrypted == TXT


def test_fernet_copy():
    fernet = Fernet.new()
    encrypted = fernet.encrypt(TXT)

    copied_fernet = copy.copy(fernet)
    decrypted = copied_fernet.decrypt(encrypted).decode()

    assert decrypted == TXT


def test_fernet_deepcopy():
    fernet = Fernet(Fernet.generate_key())
    encrypted = fernet.encrypt(TXT)

    deepcopied_fernet = copy.deepcopy(fernet)
    decrypted = deepcopied_fernet.decrypt(encrypted).decode()

    assert decrypted == TXT


def test_fernet_repr():
    fernet = Fernet.new()
    assert repr(fernet).startswith("Fernet(key=")
