"""gdb 批处理分析：提取信号 / 故障地址 / 归一化栈帧（地址与参数剥离）。"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

from ..wsl import bash, to_posix

FRAME_RE = re.compile(r"^#(?P<idx>\d+)\s+(?P<body>.+)$")
FAULT_RE = re.compile(r"VF_FAULT_ADDR=(0x[0-9a-fA-F]+|\(nil\))")
SIGNAL_RE = re.compile(r"VF_SIGNAL=(\d+)")
LINE_RE = re.compile(r"at [^:]+:(\d+)")
FUNC_IN_RE = re.compile(r"\bin ([A-Za-z_][A-Za-z0-9_.$]*)")

GDB_TEMPLATE = (
    "set pagination off\n"
    "set confirm off\n"
    "run < {crash}\n"
    'printf "VF_FAULT_ADDR=0x%lx\\n", (unsigned long)$_siginfo._sifields._sigfault.si_addr\n'
    'printf "VF_SIGNAL=%d\\n", $_siginfo.si_signo\n'
    "bt 8\n"
    "quit\n"
)


@dataclass
class GdbInfo:
    ok: bool
    signal: int = 0
    fault_addr: int = 0
    frames: list[str] = field(default_factory=list)
    error: str = ""


def normalize_frames(text: str, top: int = 5) -> list[str]:
    """从 gdb 文本中提取归一化栈帧：``函数[:源码行]``（剥离地址与参数）。"""
    frames: list[str] = []
    for raw_line in text.splitlines():
        match = FRAME_RE.match(raw_line.strip())
        if not match:
            continue
        body = match.group("body")
        func_match = FUNC_IN_RE.search(body)
        if func_match:
            func = func_match.group(1)
        else:
            tokens = body.split()
            first = tokens[0] if tokens else ""
            # 未解析帧（`in ?? ()` 或裸地址）：归一化为常量，保证去重稳定
            func = "??" if first.startswith("0x") or first.startswith("?") else first.rstrip("()")
        line_match = LINE_RE.search(body)
        frames.append(f"{func}:{line_match.group(1)}" if line_match else func)
        if len(frames) >= top:
            break
    return frames


def analyze_crash(binary: Path | str, crash: Path | str, workdir: Path | str, timeout: int = 120) -> GdbInfo:
    """在 WSL/Linux 中用 gdb 批处理分析崩溃：信号 / 故障地址 / 栈帧。"""
    binary = Path(binary)
    crash = Path(crash)
    workdir = Path(workdir)
    workdir.mkdir(parents=True, exist_ok=True)
    script = workdir / "gdb_cmds.txt"
    script.write_text(GDB_TEMPLATE.format(crash=to_posix(crash)), encoding="utf-8")

    command = f"cd {to_posix(workdir)} && gdb -batch -q -x {to_posix(script)} -args {to_posix(binary)} 2>&1"
    _code, output = bash(command, timeout=timeout)

    info = GdbInfo(ok=False)
    fault_match = FAULT_RE.search(output)
    if fault_match:
        raw_addr = fault_match.group(1)
        info.fault_addr = 0 if raw_addr == "(nil)" else int(raw_addr, 16)
    signal_match = SIGNAL_RE.search(output)
    if signal_match:
        info.signal = int(signal_match.group(1))
    info.frames = normalize_frames(output, top=5)
    info.ok = bool(info.frames) or info.signal != 0
    if not info.ok:
        info.error = output[-1500:]
    return info
