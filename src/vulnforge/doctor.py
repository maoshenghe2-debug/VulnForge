"""vulnforge doctor：环境自检（9 项）与一键修复命令。

检查项：
1. Python 版本（≥3.11）
2. 平台与 WSL（Windows 需 WSL2 + Ubuntu 可启动；Linux 原生即通过）
3. git
4. AFL++（afl-fuzz）
5. 插桩编译器（afl-clang-fast）
6. gdb（崩溃分析）
7. tree-sitter 语法（C + Python）可加载
8. 磁盘空间（工作盘 ≥5 GiB）
9. 工作目录可写（``.vulnforge/``）

Windows 下工具探测统一**经 WSL2**（AFL++ 只在 WSL 内运行）；Linux 原生直接探测。
"""

from __future__ import annotations

import platform
import shutil
import subprocess
import sys
from dataclasses import asdict, dataclass
from pathlib import Path

from . import __version__
from .errors import EXIT_CHECK_WARN, EXIT_ENV, EXIT_OK

STATUS_OK = "就绪"
STATUS_WARN = "缺失"
STATUS_FAIL = "不满足"

WSL_DISTRO = "Ubuntu"
WORKDIR_NAME = ".vulnforge"
MIN_DISK_GIB = 5.0


@dataclass
class Check:
    key: str
    name: str
    status: str
    detail: str
    fix: str = ""
    required: bool = False


def _decode(raw: bytes) -> str:
    """解码子进程输出：兼容 UTF-8 与 wsl.exe 的 UTF-16LE 混排。

    策略：先剔除空字节（UTF-16LE 的 ASCII 码位会退化为等值单字节），
    再按 UTF-8 解码——ASCII 内容（版本号 / 哨兵标记）在任何混排下均可读；
    UTF-16LE 中的中文会显示为替换字符（仅影响 wsl.exe 告警行，可接受）。
    """
    if not raw:
        return ""
    return raw.replace(b"\x00", b"").decode("utf-8", errors="replace").strip()


def _run(cmd: list[str], timeout: int = 25) -> tuple[int, str]:
    try:
        proc = subprocess.run(cmd, capture_output=True, timeout=timeout)
    except FileNotFoundError:
        return -1, "命令不存在"
    except subprocess.TimeoutExpired:
        return -2, f"超时（>{timeout}s）"
    return proc.returncode, _decode(proc.stdout + proc.stderr)


def _first_line(text: str) -> str:
    line = text.splitlines()[0].strip() if text else ""
    return line[:110]


def _is_windows() -> bool:
    return platform.system() == "Windows"


def _wsl_prefix() -> list[str]:
    return ["wsl.exe", "-d", WSL_DISTRO, "-u", "root", "--", "bash", "-lc"]


def _probe_tool(command: str, version_arg: str = "--version") -> tuple[bool, str]:
    """探测工具可用性；Windows 下经 WSL2 探测，返回（是否可用, 版本行）。"""
    script = f"command -v {command} >/dev/null 2>&1 && {command} {version_arg} 2>&1 | head -1"
    if _is_windows():
        code, out = _run([*_wsl_prefix(), script], timeout=60)
    else:
        code, out = _run(["bash", "-lc", script], timeout=30)
    return code == 0 and bool(out.strip()), _first_line(out)


def _tool_check(key: str, name: str, command: str, version_arg: str, fix: str, required: bool = False) -> Check:
    ok, line = _probe_tool(command, version_arg)
    return Check(
        key=key,
        name=name,
        status=STATUS_OK if ok else STATUS_WARN,
        detail=line if ok else f"未检测到 {command}",
        fix="" if ok else fix,
        required=required,
    )


def check_python() -> Check:
    v = sys.version_info
    ok = (v.major, v.minor) >= (3, 11)
    return Check(
        key="python",
        name="Python 版本",
        status=STATUS_OK if ok else STATUS_FAIL,
        detail=f"Python {v.major}.{v.minor}.{v.micro}（要求 ≥3.11）",
        fix="" if ok else "uv python install 3.11",
        required=True,
    )


def check_wsl() -> Check:
    if not _is_windows():
        return Check(key="wsl", name="平台 / WSL", status=STATUS_OK, detail=f"{platform.system()} 原生环境（无需 WSL）")
    code, out = _run(["wsl.exe", "-l", "-q"], timeout=30)
    if code != 0:
        return Check(
            key="wsl",
            name="平台 / WSL",
            status=STATUS_WARN,
            detail="未检测到可用 WSL",
            fix="管理员 PowerShell：wsl --install -d Ubuntu",
        )
    distros = [line.strip() for line in out.splitlines() if line.strip()]
    has_ubuntu = any(WSL_DISTRO.lower() in d.lower() for d in distros)
    detail = f"WSL 发行版：{'、'.join(distros) if distros else '无'}"
    if not has_ubuntu:
        return Check(key="wsl", name="平台 / WSL", status=STATUS_WARN, detail=detail, fix="wsl --install -d Ubuntu")
    code2, out2 = _run([*_wsl_prefix(), "echo WSL_OK"], timeout=90)
    boot_ok = code2 == 0 and "WSL_OK" in out2
    return Check(
        key="wsl",
        name="平台 / WSL",
        status=STATUS_OK if boot_ok else STATUS_FAIL,
        detail=detail + f"；Ubuntu 启动探针：{'通过' if boot_ok else '失败'}",
        fix="" if boot_ok else "wsl -d Ubuntu -u root -- bash -lc 'echo ok' 排查启动问题",
    )


def check_tree_sitter() -> Check:
    try:
        from tree_sitter_language_pack import get_parser

        for lang in ("c", "python"):
            get_parser(lang)
    except Exception as exc:  # 依赖缺失 / 加载失败都视为不满足
        return Check(
            key="tree_sitter",
            name="tree-sitter 语法（C/Python）",
            status=STATUS_FAIL,
            detail=f"加载失败：{exc}",
            fix='uv pip install -e ".[all]"',
            required=True,
        )
    return Check(key="tree_sitter", name="tree-sitter 语法（C/Python）", status=STATUS_OK, detail="C / Python 解析器加载成功", required=True)


def check_disk(base: Path) -> Check:
    anchor = base.anchor or base.drive or "/"
    usage = shutil.disk_usage(anchor)
    free_gib = usage.free / (1024**3)
    ok = free_gib >= MIN_DISK_GIB
    return Check(
        key="disk",
        name="磁盘空间",
        status=STATUS_OK if ok else STATUS_WARN,
        detail=f"{anchor} 可用 {free_gib:.1f} GiB（要求 ≥{MIN_DISK_GIB:g} GiB）",
        fix="" if ok else "清理磁盘空间或调整工作目录",
    )


def check_workdir(base: Path) -> Check:
    probe_dir = base / WORKDIR_NAME
    try:
        probe_dir.mkdir(parents=True, exist_ok=True)
        probe = probe_dir / ".write_test"
        probe.write_text("ok", encoding="utf-8")
        probe.unlink()
    except OSError as exc:
        return Check(key="workdir", name="工作目录可写", status=STATUS_FAIL, detail=f"{probe_dir}：{exc}", fix="检查目录权限", required=True)
    return Check(key="workdir", name="工作目录可写", status=STATUS_OK, detail=str(probe_dir), required=True)


def run_doctor(base: Path | None = None) -> dict:
    """运行全部检查，返回 JSON 可序列化报告（含 exit_code）。"""
    base = Path(base) if base is not None else Path.cwd()
    apt_fix = "wsl -d Ubuntu -u root -- apt-get install -y" if _is_windows() else "sudo apt-get install -y"
    checks = [
        check_python(),
        check_wsl(),
        _tool_check("git", "git", "git", "--version", f"{apt_fix} git"),
        _tool_check(
            "aflpp",
            "AFL++（afl-fuzz）",
            "afl-fuzz",
            "",
            f"{apt_fix} afl++ clang llvm",
        ),
        _tool_check(
            "afl_clang",
            "插桩编译器（afl-clang-fast）",
            "afl-clang-fast",
            "--version",
            f"{apt_fix} afl++ clang llvm",
        ),
        _tool_check("gdb", "gdb（崩溃分析）", "gdb", "--version", f"{apt_fix} gdb"),
        check_tree_sitter(),
        check_disk(base),
        check_workdir(base),
    ]
    counts = {"ok": 0, "warn": 0, "fail": 0}
    for item in checks:
        counts[{STATUS_OK: "ok", STATUS_WARN: "warn", STATUS_FAIL: "fail"}[item.status]] += 1

    fail_required = any(item.required and item.status == STATUS_FAIL for item in checks)
    if fail_required:
        exit_code = EXIT_ENV
    elif counts["warn"] or counts["fail"]:
        exit_code = EXIT_CHECK_WARN
    else:
        exit_code = EXIT_OK

    return {
        "tool": "vulnforge",
        "version": __version__,
        "platform": f"{platform.system()} {platform.release()}",
        "checks": [asdict(item) for item in checks],
        "summary": counts,
        "exit_code": exit_code,
    }
