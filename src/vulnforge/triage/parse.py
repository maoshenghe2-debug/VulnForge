"""崩溃元数据解析：AFL++ 命名约定与信号映射。

兼容两种分隔符：AFL 原生 ``id:000000,sig:11`` 与收集阶段归一化后的
``id_000000,sig_11``（Windows 侧文件名不允许冒号，收集时统一替换为下划线）。
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

SIGNAL_NAMES = {
    4: "SIGILL",
    6: "SIGABRT",
    7: "SIGBUS",
    8: "SIGFPE",
    9: "SIGKILL",
    11: "SIGSEGV",
    15: "SIGTERM",
}

_CRASH_RE = re.compile(r"id[:_](?P<id>\d+).*?sig[:_](?P<sig>\d+)")
_CRASH_NAME_RE = re.compile(r"id[:_]\d+")


@dataclass
class CrashMeta:
    file: str
    crash_id: str
    signal: int
    signal_name: str
    size: int


def parse_crash(path: Path) -> CrashMeta:
    """解析单个崩溃文件名（``id:000000,sig:11,...`` 或 ``id_000000,sig_11,...``）。"""
    path = Path(path)
    match = _CRASH_RE.search(path.name)
    signal = int(match.group("sig")) if match else 0
    return CrashMeta(
        file=str(path),
        crash_id=match.group("id") if match else "?",
        signal=signal,
        signal_name=SIGNAL_NAMES.get(signal, f"SIG{signal}"),
        size=path.stat().st_size,
    )


def list_crashes(crashes_dir: Path | str) -> list[CrashMeta]:
    """列出崩溃目录中的崩溃文件（排除 README.txt 等非崩溃文件）。"""
    crashes_dir = Path(crashes_dir)
    if not crashes_dir.is_dir():
        return []
    items = []
    for item in sorted(crashes_dir.iterdir()):
        if item.is_file() and _CRASH_NAME_RE.search(item.name):
            items.append(parse_crash(item))
    return items
