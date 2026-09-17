"""triage 测试：崩溃元数据解析 / 栈帧归一化 / 去重键 / repro 模板 / 端到端（requires_wsl）。"""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from vulnforge.triage.dedup import cluster_crashes, dedup_key
from vulnforge.triage.gdb import normalize_frames
from vulnforge.triage.parse import list_crashes, parse_crash
from vulnforge.triage.pipeline import REPRO_TEMPLATE
from vulnforge.wsl import is_windows

SAMPLE = Path(__file__).resolve().parents[1] / "src" / "vulnforge" / "range" / "samples" / "stack_overflow.c"

GDB_SAMPLE = """\
Program received signal SIGSEGV, Segmentation fault.
VF_FAULT_ADDR=0x7ffd1234abcd
VF_SIGNAL=11
#0  0x00005555555551a9 in vuln_entry (data=0x7fffffffe0d0, size=66) at /mnt/d/x/stack_overflow.c:11
#1  0x0000555555555251 in main (argc=1, argv=0x7fffffffe1c8) at /mnt/d/x/harness_main.c:35
#2  0x00007ffff7c29d90 in __libc_start_call_main () at ../sysdeps/nptl/libc_start_call_main.h:58
"""


def _has_fuzz_env() -> bool:
    if is_windows() and shutil.which("wsl") is None:
        return False
    from vulnforge.wsl import bash

    code, _ = bash(
        "command -v afl-fuzz >/dev/null 2>&1 && command -v gdb >/dev/null 2>&1 && echo OK",
        timeout=90,
    )
    return code == 0


requires_wsl = pytest.mark.skipif(not _has_fuzz_env(), reason="需要 WSL2/Linux + AFL++ + gdb 环境")


def test_parse_crash_name(tmp_path):
    crash = tmp_path / "id_000000,sig_11,src_000001,time_802,execs_17,op_havoc,rep_15"
    crash.write_bytes(b"A" * 66)
    meta = parse_crash(crash)
    assert meta.crash_id == "000000"
    assert meta.signal == 11
    assert meta.signal_name == "SIGSEGV"
    assert meta.size == 66


def test_list_crashes_filters_readme(tmp_path):
    (tmp_path / "README.txt").write_text("x", encoding="utf-8")
    (tmp_path / "id_000000,sig_11,src_000000,time_1,execs_1,op_x").write_bytes(b"1")
    items = list_crashes(tmp_path)
    assert len(items) == 1 and items[0].signal == 11


def test_normalize_frames_strips_addresses():
    frames = normalize_frames(GDB_SAMPLE, top=5)
    assert frames[0] == "vuln_entry:11"
    assert frames[1] == "main:35"
    assert len(frames) == 3
    assert all("0x" not in item for item in frames)


def test_normalize_frames_unknown_frames_are_constant():
    """未解析帧（返回地址被输入数据覆盖）必须归一化为常量 `??`，否则同一缺陷会被误判多簇。"""
    text = (
        "#0  0x00005555555551a9 in vuln_entry (data=0x1, size=66) at /x/stack_overflow.c:14\n"
        "#1  0x43b8b8b8b8b8b8b8 in ?? ()\n"
        "#2  0x0000000000401249 in ?? ()\n"
    )
    assert normalize_frames(text) == ["vuln_entry:14", "??", "??"]
    other = (
        "#0  0x00005555555551a9 in vuln_entry (data=0x1, size=64) at /x/stack_overflow.c:14\n"
        "#1  0x4141414141414141 in ?? ()\n"
        "#2  0x0000000000401249 in ?? ()\n"
    )
    assert normalize_frames(text) == normalize_frames(other)


def test_dedup_key_contract():
    base_frames = ["vuln_entry:11", "main:35"]
    key1 = dedup_key(11, base_frames, 0x7FFD1234A000)
    key2 = dedup_key(11, base_frames, 0x7FFD1234AFFF)  # 同页（>>12 相同）
    key3 = dedup_key(11, ["other_func:3"], 0x7FFD1234A000)
    key4 = dedup_key(6, base_frames, 0x7FFD1234A000)
    assert key1 == key2  # 同页不同地址 → 同键
    assert key1 != key3  # 栈帧不同 → 不同键
    assert key1 != key4  # 信号不同 → 不同键
    assert len(key1) == 16


def test_cluster_crashes_groups_same_key():
    entries = [
        {"file": "a", "signal": 11, "frames": ["vuln_entry:11", "main:35"], "fault_addr": 0x1000},
        {"file": "b", "signal": 11, "frames": ["vuln_entry:11", "main:35"], "fault_addr": 0x1FFF},
        {"file": "c", "signal": 6, "frames": ["abort_here:3"], "fault_addr": 0},
    ]
    clusters = cluster_crashes(entries)
    assert len(clusters) == 2
    assert clusters[0].members == ["a", "b"]
    assert clusters[1].members == ["c"]


def test_repro_template_is_lf_and_contract():
    blob = REPRO_TEMPLATE.format(signal=11, key="abc", top_frame="vuln_entry:11", rel_input="minimized/x")
    assert "\r" not in blob
    assert "exit 0" in blob and "exit 1" in blob
    assert "rc\" -ge 128" in blob


@requires_wsl
@pytest.mark.slow
def test_end_to_end_triage(tmp_path):
    """端到端：10s fuzz → triage → 1 个唯一缺陷簇 + repro.sh + 最小化。"""
    from vulnforge.fuzz.orchestrator import run_job
    from vulnforge.triage.pipeline import run_triage

    state = run_job(SAMPLE, name="triage-e2e", cores=2, duration_s=10, workspace=tmp_path)
    assert state["stats"]["crashes_total"] >= 1, state
    job_dir = Path(state["artifacts"]["job_dir"])
    if not job_dir.is_absolute():
        job_dir = Path.cwd() / job_dir
    result = run_triage(job_dir, minimize=True)
    assert result["ok"], result
    assert result["summary"]["clusters"] >= 1
    assert result["summary"]["clusters"] <= result["summary"]["crashes"]
    for cluster in result["clusters"]:
        assert Path(cluster["repro"]).exists()
        if cluster.get("minimized", {}).get("ok"):
            assert cluster["minimized"]["minimized_size"] <= cluster["minimized"]["original_size"]
    assert (job_dir / "triage" / "triage.json").exists()


def test_merge_r1_weak_cluster_absorbed():
    """R1：全 `??` 的归因弱簇并入同信号最强簇（无论先后）。"""
    from vulnforge.triage.dedup import cluster_crashes

    entries = [
        {"file": "weak_1", "signal": 11, "frames": ["??", "??"], "fault_addr": 0x1000},
        {"file": "strong_1", "signal": 11, "frames": ["vuln_entry:14", "??"], "fault_addr": 0x2000},
    ]
    clusters = cluster_crashes(entries)
    assert len(clusters) == 1
    assert sorted(clusters[0].members) == ["strong_1", "weak_1"]
    assert clusters[0].merged_from


def test_merge_r2_shared_source_frame():
    """R2：共享 `vuln_entry:<行号>` 源帧的同源多形态合并。"""
    from vulnforge.triage.dedup import cluster_crashes

    entries = [
        {"file": "a", "signal": 11, "frames": ["__printf_buffer:348", "vuln_entry:17"], "fault_addr": 0x3000},
        {"file": "b", "signal": 11, "frames": ["__wcsnlen_avx2:76", "vuln_entry:17"], "fault_addr": 0x4000},
    ]
    clusters = cluster_crashes(entries)
    assert len(clusters) == 1
    assert len(clusters[0].members) == 2


def test_no_merge_across_signals_or_source_lines():
    """精度：不同信号 / 不同源行不合并；弱簇并入同信号强簇（按成员数、并列取先者）。"""
    from vulnforge.triage.dedup import cluster_crashes

    entries = [
        {"file": "s11_weak", "signal": 11, "frames": ["??"], "fault_addr": 0x1000},
        {"file": "s6_abort", "signal": 6, "frames": ["__GI_abort:79"], "fault_addr": 0x1000},
        {"file": "line14", "signal": 11, "frames": ["vuln_entry:14"], "fault_addr": 0x5000},
        {"file": "line25", "signal": 11, "frames": ["vuln_entry:25"], "fault_addr": 0x6000},
    ]
    clusters = cluster_crashes(entries)
    by_member = {member: cluster for cluster in clusters for member in cluster.members}
    assert len(clusters) == 3
    assert by_member["s11_weak"].key == by_member["line14"].key  # R1 并入先出现的最强簇
    assert by_member["s6_abort"].members == ["s6_abort"]  # 跨信号不合并
    assert by_member["line25"].key != by_member["line14"].key  # 不同源行不合并
