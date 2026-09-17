"""fuzz 编排测试：状态契约单元测试 + WSL2 端到端（requires_wsl）。"""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from vulnforge.fuzz.orchestrator import (
    DEFAULT_SEEDS,
    new_job_dir,
    parse_fuzzer_stats,
    prepare_corpus,
    write_run_sh,
    write_state,
)
from vulnforge.wsl import is_windows, to_posix

SAMPLE = (
    Path(__file__).resolve().parents[1] / "src" / "vulnforge" / "range" / "samples" / "stack_overflow.c"
)


def _has_fuzz_env() -> bool:
    if is_windows() and shutil.which("wsl") is None:
        return False
    from vulnforge.wsl import bash

    code, _ = bash(
        "command -v afl-fuzz >/dev/null 2>&1 && command -v afl-clang-fast >/dev/null 2>&1 && echo OK",
        timeout=90,
    )
    return code == 0


requires_wsl = pytest.mark.skipif(not _has_fuzz_env(), reason="需要 WSL2/Linux + AFL++ 环境")


def test_new_job_dir_and_corpus(tmp_path):
    job = new_job_dir("demo", base=tmp_path)
    assert job.is_dir() and (job / "corpus").is_dir()
    count = prepare_corpus(job)
    assert count == len(DEFAULT_SEEDS)
    files = sorted((job / "corpus").iterdir())
    assert files[1].read_bytes() == b"A" * 64


def test_prepare_corpus_from_seeds(tmp_path):
    seeds = tmp_path / "seeds"
    seeds.mkdir()
    (seeds / "one").write_bytes(b"1")
    (seeds / "two").write_bytes(b"22")
    job = new_job_dir("s", base=tmp_path)
    assert prepare_corpus(job, seeds) == 2
    assert (job / "corpus" / "one").read_bytes() == b"1"


def test_write_state_atomic(tmp_path):
    job = tmp_path / "j"
    job.mkdir()
    write_state(job, {"schema_version": 1, "job": {}, "workers": [], "stats": {}})
    data = json.loads((job / "state.json").read_text(encoding="utf-8"))
    assert data["schema_version"] == 1
    assert "updated_at" in data
    assert not (job / "state.json.tmp").exists()


def test_write_run_sh_contract(tmp_path):
    job = tmp_path / "j"
    job.mkdir()
    script = write_run_sh(job, cores=2, duration_s=30, resume=False)
    blob = script.read_bytes()
    assert b"\r" not in blob  # 必须 LF（bash 兼容）
    text = blob.decode("utf-8")
    assert "AFL_SKIP_CPUFREQ=1" in text
    assert "-M main" in text and "-S s1" in text
    assert '-V "30"' in text
    resume_script = write_run_sh(job, cores=1, duration_s=5, resume=True)
    assert "-i-" in resume_script.read_text(encoding="utf-8")
    # 崩溃收集块（在脚本内完成；':'→'_' 归一化——wsl.exe 字符串方式会吞掉通配符，勿改回）
    assert "mkdir -p crashes" in text
    assert "tr ':' '_'" in text
    assert "crashes/${inst}_" in text


def test_parse_fuzzer_stats(tmp_path):
    inst = tmp_path / "out" / "main"
    inst.mkdir(parents=True)
    (inst / "fuzzer_stats").write_text(
        "start_time        : 1\n"
        "execs_done        : 1234\n"
        "execs_per_sec     : 456.7\n"
        "saved_crashes     : 2\n"
        "paths_total       : 33\n"
        "run_time          : 10\n",
        encoding="utf-8",
    )
    stats = parse_fuzzer_stats(inst / "fuzzer_stats")
    assert stats["instance"] == "main"
    assert stats["execs_done"] == 1234
    assert stats["saved_crashes"] == 2
    assert stats["execs_per_sec"] == pytest.approx(456.7)


def test_to_posix_path():
    out = to_posix(Path("D:/AI-Project/x"))
    if is_windows():
        assert out.startswith("/mnt/d/")
        assert "\\" not in out
    else:
        assert out.startswith("/")


@requires_wsl
def test_end_to_end_fuzz_finds_crash(tmp_path):
    """端到端：对栈溢出样本跑 30s × 2 核，必须产出 ≥1 个崩溃（评审 W1 前置条件）。"""
    from vulnforge.fuzz.orchestrator import run_job

    state = run_job(SAMPLE, name="smoke", cores=2, duration_s=30, workspace=tmp_path)
    assert state["job"]["status"] == "completed", state["job"]
    assert state["stats"]["execs_total"] > 0
    assert state["stats"]["crashes_total"] >= 1, state
    crashes = state["artifacts"]["crash_files"]
    assert crashes and Path(crashes[0]).exists()
    assert (tmp_path / "jobs" / state["job"]["id"] / "state.json").exists()
