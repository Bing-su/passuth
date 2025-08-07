import sysconfig

import nox


@nox.session(python=["3.9", "3.13", "3.13t", "pypy3.11"], venv_backend="uv")
def test(session: nox.Session) -> None:
    py_gil_disabled = sysconfig.get_config_var("Py_GIL_DISABLED")
    if py_gil_disabled:
        session.install(".[test]")
    else:
        session.install(".[test,test-extra]")
    session.run("pytest", "-v", *session.posargs)
