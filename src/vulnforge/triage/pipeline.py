"""triage 流水线：解析 → gdb 分析 → 去重 → 最小化 → repro 脚本（repro.sh 契约：0=复现 / 1=未复现）。"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

from .. import __version__
from .dedup import cluster_crashes
from .gdb import analyze_crash
from .minimize import minimize_crash
from .parse import list_crashes

REPRO_TEMPLATE = """#!/usr/bin/env bash
# VulnForge 复现脚本（退出码：0=复现 / 1=未复现）
# 信号：{signal} · 去重键：{key} · 栈顶：{top_frame}
cd "$(dirname "$0")" || exit 1
BIN="../build/target"
INPUT="../{rel_input}"
"$BIN" < "$INPUT"
rc=$?
if [ "$rc" -ge 128 ]; then
  echo "[复现] 目标以信号 $((rc - 128)) 终止"
  exit 0
fi
echo "[未复现] 退出码 $rc"
exit 1
"""


def run_triage(job_dir: Path | str, *, minimize: bool = True, limit: int | None = None) -> dict:
    """执行分类流水线并落盘 ``triage/triage.json``。"""
    job_dir = Path(job_dir)
    crashes = list_crashes(job_dir / "crashes")
    if limit:
        crashes = crashes[:limit]
    if not crashes:
        return {"ok": False, "error": "未找到崩溃文件（crashes/ 目录为空）", "crashes": [], "clusters": []}

    binary = job_dir / "build" / "target"
    triage_dir = job_dir / "triage"
    triage_dir.mkdir(exist_ok=True)

    entries: list[dict] = []
    for meta in crashes:
        info = analyze_crash(binary, Path(meta.file), triage_dir)
        entries.append(
            {
                "file": meta.file,
                "crash_id": meta.crash_id,
                "signal": info.signal or meta.signal,
                "signal_name": meta.signal_name,
                "frames": info.frames,
                "fault_addr": info.fault_addr,
                "gdb_ok": info.ok,
            }
        )

    clusters = cluster_crashes(entries)
    repro_dir = job_dir / "repro"
    minimized_dir = job_dir / "minimized"
    # 清理上一轮生成的产物（repro / minimized 为生成目录，重复运行时保持最新）
    for stale_dir in (repro_dir, minimized_dir):
        if stale_dir.is_dir():
            for stale in stale_dir.iterdir():
                if stale.is_file():
                    stale.unlink()
    repro_dir.mkdir(exist_ok=True)

    cluster_out = []
    for cluster in clusters:
        rep_file = cluster.members[0]
        entry: dict = {
            "key": cluster.key,
            "signal": cluster.signal,
            "frames": cluster.frames,
            "count": len(cluster.members),
            "members": cluster.members,
            "merged_from": list(cluster.merged_from),
        }
        if minimize:
            minfo = minimize_crash(binary, Path(rep_file), minimized_dir)
            entry["minimized"] = minfo
            input_file = minfo["minimized"] or rep_file
        else:
            input_file = rep_file
        try:
            rel_input = str(Path(input_file).relative_to(job_dir)).replace("\\", "/")
        except ValueError:
            rel_input = str(input_file).replace("\\", "/")
        script_path = repro_dir / f"{cluster.key}.sh"
        script_path.write_bytes(
            REPRO_TEMPLATE.format(
                signal=cluster.signal,
                key=cluster.key,
                top_frame=cluster.frames[0] if cluster.frames else "?",
                rel_input=rel_input,
            ).encode("utf-8")
        )
        entry["repro"] = str(script_path)
        cluster_out.append(entry)

    report = {
        "schema_version": 1,
        "tool": "vulnforge",
        "tool_version": __version__,
        "generated_at": datetime.now(UTC).isoformat(timespec="seconds"),
        "job_dir": str(job_dir),
        "crashes": entries,
        "clusters": cluster_out,
        "summary": {"crashes": len(entries), "clusters": len(cluster_out)},
    }
    (triage_dir / "triage.json").write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    return {"ok": True, **report}
