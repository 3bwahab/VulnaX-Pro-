"""Async subprocess runner with timeout, kill-tree, and stdin streaming."""
from __future__ import annotations

import asyncio
import shutil
import sys
from dataclasses import dataclass


@dataclass
class ProcResult:
    returncode: int
    stdout: str
    stderr: str
    timed_out: bool = False


def which(binary: str) -> str | None:
    return shutil.which(binary)


async def run_process(
    cmd: list[str],
    stdin_data: str | None = None,
    timeout: float = 120.0,
) -> ProcResult:
    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdin=asyncio.subprocess.PIPE if stdin_data is not None else None,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        out, err = await asyncio.wait_for(
            proc.communicate(stdin_data.encode() if stdin_data else None),
            timeout=timeout,
        )
    except asyncio.TimeoutError:
        _kill_tree(proc)
        try:
            await proc.wait()
        except Exception:
            pass
        return ProcResult(returncode=-1, stdout="", stderr="timeout", timed_out=True)
    return ProcResult(
        returncode=proc.returncode or 0,
        stdout=out.decode("utf-8", "replace"),
        stderr=err.decode("utf-8", "replace"),
    )


def _kill_tree(proc: asyncio.subprocess.Process) -> None:
    try:
        if sys.platform == "win32":
            import subprocess

            subprocess.run(
                ["taskkill", "/F", "/T", "/PID", str(proc.pid)],
                capture_output=True,
            )
        else:
            proc.kill()
    except Exception:
        pass
