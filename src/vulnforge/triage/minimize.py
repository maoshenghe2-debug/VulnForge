"""崩溃输入最小化（afl-tmin；失败时保留原输入并如实记录）。"""

from __future__ import annotations

from pathlib import Path

from ..wsl import bash, to_posix

MINIMIZE_ENV = "export AFL_SKIP_CPUFREQ=1; export AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1; "


def minimize_crash(
    binary: Path | str,
    crash: Path | str,
    out_dir: Path | str,
    *,
    timeout: int = 240,
) -> dict:
    """用 afl-tmin 最小化崩溃输入。返回 {ok, minimized, original_size, minimized_size, output_tail}。"""
    binary = Path(binary)
    crash = Path(crash)
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    out_file = out_dir / f"min_{crash.name}"

    command = (
        MINIMIZE_ENV
        + f"afl-tmin -i {to_posix(crash)} -o {to_posix(out_file)} -m none -- {to_posix(binary)} 2>&1 | tail -3"
    )
    _code, output = bash(command, timeout=timeout)
    ok = out_file.exists() and out_file.stat().st_size > 0
    return {
        "ok": ok,
        "minimized": str(out_file) if ok else "",
        "original_size": crash.stat().st_size,
        "minimized_size": out_file.stat().st_size if ok else 0,
        "output_tail": "" if ok else output[-500:],
    }
