import re

import nox


@nox.session(
    python=["3.9", "3.14", "3.14t", "pypy3.11", "graalpy3.12"], venv_backend="uv"
)
def test(session: nox.Session) -> None:
    if isinstance(session.python, str) and re.match(r"^3\.\d+$", session.python):
        session.install(".[test,test-extra]")
    else:
        session.install(".[test]")
    session.run("pytest", "-v", *session.posargs)
