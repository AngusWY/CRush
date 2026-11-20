
from __future__ import annotations

import os
import signal
import subprocess
import time
from pathlib import Path

from .models import CommandResult


def run_command(command: tuple[str, ...], cwd: Path, *, timeout: float,
                env: dict[str, str] | None = None) -> CommandResult:
    started = time.monotonic()
    try:
        proc = subprocess.Popen(command, cwd=cwd, text=True, errors="replace",
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True,
            env=env if env is not None else os.environ.copy())
    except OSError as exc:
        return CommandResult(command, str(cwd), 127, "", str(exc), time.monotonic() - started)
    timed_out = False
    try:
        stdout, stderr = proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        timed_out = True
        for sig, grace in ((signal.SIGTERM, 2), (signal.SIGKILL, None)):
            try:
                os.killpg(proc.pid, sig)
            except ProcessLookupError:
                pass
            try:
                stdout, stderr = proc.communicate(timeout=grace)
                break
            except subprocess.TimeoutExpired:
                continue


        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
    return CommandResult(command, str(cwd), 124 if timed_out else proc.returncode,
                         stdout, stderr, time.monotonic() - started, timed_out)
