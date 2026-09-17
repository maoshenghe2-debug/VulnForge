"""跨环境执行工具：Windows 经 WSL2（Ubuntu），Linux 原生执行。

约定：
- Windows：一切 Linux 工具（AFL++ / clang / gdb）通过 ``wsl.exe -d Ubuntu -u root`` 调用；
- Linux：直接 ``bash -lc`` 执行（CI 与服务器场景）；
- ``to_posix``：把 Windows 路径映射为 WSL 内的 ``/mnt/<drive>/...`` 路径。
"""

from __future__ import annotations

import platform
import re
import subprocess
from pathlib import Path

DISTRO = "Ubuntu"
_ANSI_RE = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]")


def is_windows() -> bool:
    return platform.system() == "Windows"


def decode(raw: bytes) -> str:
    """解码子进程输出：剔除空字节（UTF-16LE ASCII 位退化）→ 剥离 ANSI 转义 → UTF-8。"""
    if not raw:
        return ""
    text = raw.replace(b"\x00", b"").decode("utf-8", errors="replace")
    return _ANSI_RE.sub("", text).strip()


def run(cmd: list[str], timeout: int = 120) -> tuple[int, str]:
    """执行命令并捕获输出。返回（退出码, 合并输出文本）。"""
    try:
        proc = subprocess.run(cmd, capture_output=True, timeout=timeout)
    except FileNotFoundError:
        return -1, "命令不存在"
    except subprocess.TimeoutExpired:
        return -2, f"超时（>{timeout}s）"
    return proc.returncode, decode(proc.stdout + proc.stderr)


def bash(script: str, timeout: int = 120) -> tuple[int, str]:
    """在目标环境执行 bash 脚本（Windows 经 WSL2；Linux 原生）。"""
    if is_windows():
        return run(["wsl.exe", "-d", DISTRO, "-u", "root", "--", "bash", "-lc", script], timeout=timeout)
    return run(["bash", "-lc", script], timeout=timeout)


def to_posix(path: str | Path) -> str:
    """Windows 路径 → WSL 内路径（``D:/x`` → ``/mnt/d/x``）；Linux 下原样返回绝对路径。"""
    p = Path(path).resolve()
    if not is_windows():
        return str(p)
    drive = p.drive.rstrip(":")
    rest = str(p)[len(p.drive) :].replace("\\", "/")
    return f"/mnt/{drive.lower()}{rest}"
