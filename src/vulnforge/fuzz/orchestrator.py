"""AFL++ 单引擎编排：构建 → 语料 → 多核运行 → 状态契约（断点续跑）→ 崩溃收集。

契约（docs/08 §4 冻结）：
- ``state.json``：``schema_version`` / ``job`` / ``workers`` / ``stats``，
  **≤5s 周期原子写**（tmp + os.replace）；
- ``build.json``：由 ``build.build_target`` 落盘（插桩产物与参数）；
- 断点续跑：``run.sh`` 使用 ``-i-`` 恢复；``STOP`` 文件触发优雅停止。

运行环境：Windows 经 WSL2（Ubuntu），Linux 原生。
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import time
from datetime import UTC, datetime
from pathlib import Path

from .. import __version__
from ..wsl import DISTRO, bash, is_windows, to_posix
from .build import build_target

WORKSPACE = Path(".vulnforge")
STATE_INTERVAL_S = 3.0
DEFAULT_SEEDS = (b"A", b"A" * 64, bytes(range(256)))


# ------------------------------------------------------------------ 目录与语料


def new_job_dir(name: str, base: Path | str = WORKSPACE) -> Path:
    ts = datetime.now().strftime("%Y%m%d-%H%M%S")
    job = Path(base) / "jobs" / f"{name}-{ts}"
    (job / "corpus").mkdir(parents=True, exist_ok=True)
    return job


def prepare_corpus(job: Path, seeds: Path | None = None) -> int:
    """准备种子语料：复制用户种子，或写入内置最小种子集。返回种子数量。"""
    corpus = job / "corpus"
    corpus.mkdir(parents=True, exist_ok=True)
    count = 0
    if seeds is not None and Path(seeds).is_dir():
        for item in sorted(Path(seeds).iterdir()):
            if item.is_file():
                shutil.copy2(item, corpus / item.name)
                count += 1
    if count == 0:
        for idx, blob in enumerate(DEFAULT_SEEDS, start=1):
            (corpus / f"seed_{idx}").write_bytes(blob)
            count += 1
    return count


# ------------------------------------------------------------------ 运行脚本


def write_run_sh(job: Path, *, cores: int, duration_s: int, resume: bool) -> Path:
    """生成 run.sh（LF 行尾；含 STOP 优雅停止与 RUN_DONE 标记）。"""
    input_flag = "-i-" if resume else "-i corpus"
    launches = []
    for idx in range(cores):
        inst = "main" if idx == 0 else f"s{idx}"
        mode = "-M main" if idx == 0 else f"-S {inst}"
        launches.append(
            f'afl-fuzz {input_flag} -o out {mode} -V "{duration_s}" -m none -- build/target '
            f'> "logs_{inst}.txt" 2>&1 &'
        )
    script = (
        "#!/usr/bin/env bash\n"
        "# VulnForge 运行脚本（生成物；断点续跑使用 -i-）\n"
        "set -u\n"
        'cd "$(dirname "$0")"\n'
        "export AFL_SKIP_CPUFREQ=1\n"
        "export AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1\n"
        "export AFL_NO_UI=1\n"
        "mkdir -p out\n"
        + "\n".join(launches)
        + "\n"
        "pid_file=pids.txt\n"
        "jobs -p > \"$pid_file\"\n"
        "while :; do\n"
        "  alive=0\n"
        "  while read -r p; do kill -0 \"$p\" 2>/dev/null && alive=1; done < \"$pid_file\"\n"
        '  [ "$alive" -eq 0 ] && break\n'
        '  if [ -f STOP ]; then\n'
        "    while read -r p; do kill \"$p\" 2>/dev/null; done < \"$pid_file\"\n"
        "    sleep 1\n"
        "    break\n"
        "  fi\n"
        "  sleep 2\n"
        "done\n"
        "wait 2>/dev/null\n"
        "echo DONE > RUN_DONE\n"
    )
    path = job / "run.sh"
    path.write_bytes(script.encode("utf-8"))  # 显式 LF：不要用 write_text（Windows 会转 CRLF）
    return path


# ------------------------------------------------------------------ 状态与统计


def parse_fuzzer_stats(stats_file: Path) -> dict:
    """解析单个实例的 fuzzer_stats（key: value 文本）。"""
    raw: dict[str, str] = {}
    text = stats_file.read_text(encoding="utf-8", errors="replace")
    for line in text.splitlines():
        if ":" in line:
            key, _, value = line.partition(":")
            raw[key.strip()] = value.strip()

    def _int(key: str) -> int:
        try:
            return int(float(raw.get(key, "0")))
        except (TypeError, ValueError):
            return 0

    def _float(key: str) -> float:
        try:
            return float(raw.get(key, "0"))
        except (TypeError, ValueError):
            return 0.0

    return {
        "instance": stats_file.parent.name,
        "execs_done": _int("execs_done"),
        "execs_per_sec": _float("execs_per_sec"),
        "saved_crashes": _int("saved_crashes"),
        "paths_total": _int("paths_total"),
        "run_time": _int("run_time"),
        "last_update": raw.get("last_update", ""),
    }


def read_out_stats(out_dir: Path) -> list[dict]:
    if not out_dir.is_dir():
        return []
    return [parse_fuzzer_stats(item) for item in sorted(out_dir.glob("*/fuzzer_stats"))]


def write_state(job: Path, state: dict) -> None:
    """原子写 state.json（tmp + os.replace）。"""
    state["updated_at"] = datetime.now(UTC).isoformat(timespec="seconds")
    tmp = job / "state.json.tmp"
    tmp.write_text(json.dumps(state, ensure_ascii=False, indent=2), encoding="utf-8")
    os.replace(tmp, job / "state.json")


def _aggregate(workers: list[dict]) -> dict:
    return {
        "execs_total": sum(item["execs_done"] for item in workers),
        "execs_per_sec": round(sum(item["execs_per_sec"] for item in workers), 1),
        "paths_total": sum(item["paths_total"] for item in workers),
        "crashes_total": sum(item["saved_crashes"] for item in workers),
    }


# ------------------------------------------------------------------ 主流程


def request_stop(job: Path | str) -> bool:
    """请求优雅停止（写 STOP 标记，由 run.sh 处理）。"""
    job = Path(job)
    if not job.is_dir():
        return False
    (job / "STOP").write_text("stop\n", encoding="utf-8")
    return True


def run_job(
    target_src: str | Path,
    *,
    name: str | None = None,
    cores: int = 4,
    duration_s: int = 60,
    seeds: str | Path | None = None,
    resume: str | Path | None = None,
    workspace: str | Path = WORKSPACE,
    poll_interval: float = STATE_INTERVAL_S,
) -> dict:
    """执行一次 fuzz 任务（阻塞至结束），返回最终 state 字典。

    - 新建：创建 job 目录 → 构建 → 语料 → 多核运行 → 收集崩溃；
    - 续跑（``resume`` 指向既有 job 目录）：复用构建产物与语料，使用 ``-i-`` 恢复。
    """
    if resume is not None:
        job = Path(resume)
        if not job.is_dir():
            raise FileNotFoundError(f"任务目录不存在：{job}")
        build_dir = job / "build"
        target = Path(((build_dir / "build.json").exists() and json.loads((build_dir / "build.json").read_text(encoding="utf-8"))["target_source"]) or target_src)
    else:
        job = new_job_dir(name or Path(target_src).stem, base=workspace)
        (job / "build").mkdir(parents=True, exist_ok=True)
        target = Path(target_src)

    state = {
        "schema_version": 1,
        "tool": "vulnforge",
        "tool_version": __version__,
        "job": {
            "id": job.name,
            "name": name or Path(target).stem,
            "target": str(target.resolve()),
            "cores": cores,
            "duration_s": duration_s,
            "status": "building" if resume is None else "resuming",
            "started_at": datetime.now(UTC).isoformat(timespec="seconds"),
        },
        "workers": [],
        "stats": {"execs_total": 0, "execs_per_sec": 0.0, "paths_total": 0, "crashes_total": 0},
        "artifacts": {"job_dir": str(job), "build": "build.json", "out": "out", "crashes": "crashes"},
    }
    write_state(job, state)

    if resume is None:
        build = build_target(target, job / "build")
        if not build["ok"]:
            state["job"]["status"] = "failed"
            state["job"]["error"] = "构建失败：见 build/build.json 的 output_tail"
            write_state(job, state)
            return state
        prepare_corpus(job, Path(seeds) if seeds else None)

    script = write_run_sh(job, cores=cores, duration_s=duration_s, resume=resume is not None)
    state["job"]["status"] = "running"
    write_state(job, state)

    if is_windows():
        cmd = ["wsl.exe", "-d", DISTRO, "-u", "root", "--", "bash", to_posix(script)]
    else:
        cmd = ["bash", str(script)]
    log_path = job / "runner.log"
    with open(log_path, "wb") as log_fh:
        proc = subprocess.Popen(cmd, stdout=log_fh, stderr=subprocess.STDOUT)

    deadline = time.time() + duration_s + 300
    while True:
        if (job / "RUN_DONE").exists():
            break
        if proc.poll() is not None:
            break
        if time.time() > deadline:
            if is_windows():
                subprocess.run(["wsl.exe", "-d", DISTRO, "-u", "root", "--", "pkill", "-f", "afl-fuzz"], capture_output=True)
            state["job"]["status"] = "timeout"
            break
        workers = read_out_stats(job / "out")
        if workers:
            state["workers"] = [
                {
                    "name": item["instance"],
                    "execs_done": item["execs_done"],
                    "execs_per_sec": item["execs_per_sec"],
                    "crashes": item["saved_crashes"],
                    "paths_total": item["paths_total"],
                }
                for item in workers
            ]
            state["stats"] = _aggregate(workers)
        write_state(job, state)
        time.sleep(poll_interval)

    proc.wait(timeout=60)
    workers = read_out_stats(job / "out")
    if workers:
        state["workers"] = [
            {
                "name": item["instance"],
                "execs_done": item["execs_done"],
                "execs_per_sec": item["execs_per_sec"],
                "crashes": item["saved_crashes"],
                "paths_total": item["paths_total"],
            }
            for item in workers
        ]
        state["stats"] = _aggregate(workers)

    # 收集崩溃：WSL/Linux 内 cp 到统一目录，随后做名称归一化——
    # AFL 文件名含 ':'，Windows/DrvFs 暴露为私有区字符 U+F03A，统一替换为 '_'（双平台一致）
    crashes_dir = job / "crashes"
    crashes_dir.mkdir(exist_ok=True)
    collect_cmd = (
        f"cd {to_posix(job)} && mkdir -p crashes && "
        "for f in out/*/crashes/id*; do "
        '[ -f "$f" ] || continue; '
        'inst=$(basename "$(dirname "$(dirname "$f")")"); '
        'cp "$f" "crashes/${inst}_$(basename "$f")"; '
        "done"
    )
    _code, _output = bash(collect_cmd, timeout=120)
    for item in list(crashes_dir.iterdir()):
        if item.is_file():
            new_name = item.name.replace("\uf03a", "_").replace(":", "_")
            if new_name != item.name:
                item.rename(crashes_dir / new_name)
    collected = sorted(str(item) for item in crashes_dir.glob("*") if item.is_file())
    state["artifacts"]["crash_files"] = collected

    if state["job"]["status"] not in ("timeout", "failed"):
        state["job"]["status"] = "stopped" if (job / "STOP").exists() else "completed"
    write_state(job, state)
    return state
