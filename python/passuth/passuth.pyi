__version__: str

def generate_hash(password: str | bytes | bytearray) -> str: ...
def verify_password(password: str | bytes | bytearray, hash: str) -> bool: ...  # noqa: A002
