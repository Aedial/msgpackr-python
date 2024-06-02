import subprocess  # nosec B404
import sys
from typing import Any, Optional

import pytest


def _run(*arguments, show_command: bool = True, cwd: Optional[Any] = None, silent: bool = False):
    """
    Run a command with subprocess

    :param arguments: Arguments to pass to the command
    :param show_command: Whether to print the command before running it
    :param cwd: Current working directory for the command
    :param silent: Whether to suppress the output of the command and return it instead
    """

    arguments = [str(e) for e in arguments]

    if show_command:
        print(">", *arguments)

    kwargs = {}
    if cwd is not None:
        kwargs["cwd"] = cwd

    if silent:
        return subprocess.check_output(arguments, text=True, **kwargs)  # nosec B603

    return subprocess.check_call(arguments, text=True, **kwargs)  # nosec B603


def _exit_if_return_code(code: int):
    """
    Exit if the return code is not 0 (error happened)
    """

    if code:
        sys.exit(code)


def test():
    _exit_if_return_code(pytest.main(["tests/"]))
