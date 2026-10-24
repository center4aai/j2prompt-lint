"""Run the j2prompt-lint CLI inside the playground's Python runtime.

The Web Worker passes command-line arguments to ``run_cli``. It calls the
CLI's own ``main()`` and returns the exit code, stdout and stderr as strings.
The caller's ``sys.argv`` is restored even when argument parsing exits.
"""

from __future__ import annotations

import contextlib
import io
import sys
from collections.abc import Sequence
from typing import NamedTuple

from j2prompt_lint.cli.main import main

#: The program name a shell would pass as ``argv[0]``; argparse prints it in
#: usage and error messages, so it must be the console script's own name.
PROG = "j2prompt-lint"


class CliRun(NamedTuple):
    """What one CLI invocation returned and printed."""

    exit_code: int
    stdout: str
    stderr: str


def exit_code_of(code: object) -> int:
    """Return the process exit status a ``SystemExit`` code stands for.

    Args:
        code: ``SystemExit.code`` as raised (``None``, an int, or a message).

    Returns:
        0 for ``None``, the integer itself, and 1 for a message, which is what
        CPython does when such an exception ends a process.
    """
    if code is None:
        return 0
    if isinstance(code, int):
        return code
    return 1


def run_cli(argv: Sequence[str]) -> CliRun:
    """Run ``j2prompt-lint *argv`` in this process and capture its output.

    Args:
        argv: The arguments after the program name, as a shell passes them.

    Returns:
        The exit code, and everything written to stdout and stderr.
    """
    stdout = io.StringIO()
    stderr = io.StringIO()
    saved_argv = sys.argv
    sys.argv = [PROG, *argv]
    try:
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            try:
                code = main()
            except SystemExit as stop:  # argparse refuses a command line this way
                code = exit_code_of(stop.code)
    finally:
        sys.argv = saved_argv
    return CliRun(code, stdout.getvalue(), stderr.getvalue())
