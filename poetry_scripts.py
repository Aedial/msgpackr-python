import subprocess  # nosec B404
import sys
from argparse import ArgumentParser
from pathlib import Path
from typing import Any, Optional

import pytest

ROOT = Path(__file__).parent.resolve()


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


def build_docs():
    _run("make", "html", cwd=str(ROOT / "docs"))


def bump_version():
    bump_types = ["major", "minor", "patch"]

    parser = ArgumentParser()
    parser.add_argument("bump", choices=bump_types, help="Bump type")
    args = parser.parse_args()

    # Check for staged files (you don't want to accidentally commit them)
    staged_files = _run("git", "diff", "--name-only", "--cached", show_command=False, silent=True)
    if staged_files:
        raise RuntimeError(f"Staged files, commit them before bumping version:\n{staged_files}")

    # Bump the pyproject.toml and get the versions

    current_version = _run("poetry", "version", "-s", show_command=False, silent=True).strip()
    _run("poetry", "version", args.bump)
    bumped_version = _run("poetry", "version", "-s", show_command=False, silent=True).strip()

    # Create README from the template
    format_args = {"current_version": current_version, "bumped_version": bumped_version}

    readme = (ROOT / "README_TEMPLATE.md").read_text("utf-8")
    (ROOT / "README.md").write_text(readme.format(**format_args))

    # Commit the bump
    commit_message = f"[MISC] Bump version - {args.bump}: {current_version} -> {bumped_version}"
    _run("git", "add", "README.md", "pyproject.toml")
    _run("git", "commit", "-m", commit_message)

    # Commit the tag
    _run("git", "tag", "-a", f"v{bumped_version}")

    print(
        "You can now push the commit and the tag with `git push --follow-tags`.\n"
        "Ensure you're ready to push with `git status` and `git log`."
    )
