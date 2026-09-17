"""构建插桩目标：afl-clang-fast + 通用 harness（WSL2 / Linux）。

契约（docs/08 §4）：产物目录写入 ``build.json``（插桩编译产物与参数）。
"""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path

from .. import __version__
from ..wsl import bash, is_windows, to_posix

HARNESS_MAIN = Path(__file__).parent / "assets" / "harness_main.c"

DEFAULT_FLAGS = ["-O1", "-g", "-fno-omit-frame-pointer"]


def build_target(
    src: str | Path,
    out_dir: str | Path,
    *,
    binary_name: str = "target",
    extra_flags: list[str] | None = None,
    timeout: int = 600,
) -> dict:
    """用 afl-clang-fast 编译（自动附加通用 harness），返回并落盘 build.json。"""
    src = Path(src).resolve()
    out_dir = Path(out_dir).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)
    flags = DEFAULT_FLAGS + list(extra_flags or [])
    binary = out_dir / binary_name

    script = " && ".join(
        [
            f"mkdir -p {to_posix(out_dir)}",
            "afl-clang-fast "
            + " ".join(flags)
            + f" -o {to_posix(binary)} {to_posix(src)} {to_posix(HARNESS_MAIN)}",
        ]
    )
    code, output = bash(script, timeout=timeout)
    ok = code == 0 and binary.exists()

    build = {
        "schema_version": 1,
        "tool": "vulnforge",
        "tool_version": __version__,
        "compiler": "afl-clang-fast",
        "flags": flags,
        "target_source": str(src),
        "harness": str(HARNESS_MAIN),
        "binary": str(binary),
        "environment": "wsl2-ubuntu" if is_windows() else "linux",
        "ok": ok,
        "built_at": datetime.now(UTC).isoformat(timespec="seconds"),
    }
    if ok:
        build["sha256"] = hashlib.sha256(binary.read_bytes()).hexdigest()
        build["size"] = binary.stat().st_size
    else:
        build["output_tail"] = output[-2000:]

    (out_dir / "build.json").write_text(json.dumps(build, ensure_ascii=False, indent=2), encoding="utf-8")
    return build


def compiler_available() -> bool:
    """探测 afl-clang-fast 是否可用（当前环境 / WSL）。"""
    code, _ = bash("command -v afl-clang-fast >/dev/null 2>&1 && echo OK", timeout=60)
    return code == 0
