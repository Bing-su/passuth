import platform
import re

import nox

py = ["3.12", "3.15", "3.15t", "pypy3.12"]
if platform.system() != "Windows":
    py.append("graalpy3.13")


@nox.session(python=py, venv_backend="uv")
def test(session: nox.Session) -> None:
    if isinstance(session.python, str) and re.match(r"^3\.\d+t?$", session.python):
        session.install(".[test,test-extra]")
    else:
        session.install(".[test]")
    session.run("pytest", "-v", *session.posargs)
