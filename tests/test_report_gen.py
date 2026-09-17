"""报告生成测试：从 golden 数据构造任务目录 → schema 校验 → Markdown 内容断言。"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from vulnforge.report.generator import generate_report, to_markdown, validate_report

GOLDEN_PATH = Path(__file__).parent / "golden" / "golden_crashes.json"


def _make_job(tmp_path: Path) -> Path:
    """用 golden 第一条任务数据构造最小可用任务目录（build/state/triage/crashes/repro）。"""
    golden = json.loads(GOLDEN_PATH.read_text(encoding="utf-8"))
    job = tmp_path / "demo-job-001"
    (job / "build").mkdir(parents=True)
    (job / "triage").mkdir()
    (job / "crashes").mkdir()
    (job / "repro").mkdir()
    (job / "minimized").mkdir()

    # build.json / state.json
    (job / "build" / "build.json").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "compiler": "afl-clang-fast",
                "flags": ["-O1", "-g"],
                "target_source": str(tmp_path / "target.c"),
                "binary": str(job / "build" / "target"),
                "environment": "linux",
                "ok": True,
                "sha256": "a" * 64,
            }
        ),
        encoding="utf-8",
    )
    (job / "state.json").write_text(
        json.dumps({"job": {"cores": 2, "duration_s": 30}, "stats": {"execs_total": 10000, "crashes_total": 2}}),
        encoding="utf-8",
    )
    # 目标源码（提供静态命中）
    (tmp_path / "target.c").write_text(
        "#include <string.h>\nvoid handle(char *in) {\n    char buf[32];\n    strcpy(buf, in);\n}\n",
        encoding="utf-8",
    )

    # 崩溃文件与 triage.json（取 golden 第一条）
    job_entry = golden["jobs"][0]
    members = []
    for crash in job_entry["crashes"]:
        crash_file = job / "crashes" / crash["file"]
        crash_file.write_bytes(b"A" * 66)
        members.append(str(crash_file))
    minimized_file = job / "minimized" / "min_crash"
    minimized_file.write_bytes(b"A" * 41)
    repro_script = job / "repro" / "key123.sh"
    repro_script.write_bytes(b"#!/usr/bin/env bash\nexit 0\n")
    triage = {
        "schema_version": 1,
        "crashes": [
            {
                "file": member,
                "signal": job_entry["crashes"][0]["signal"],
                "frames": job_entry["crashes"][0]["frames"],
                "fault_addr": job_entry["crashes"][0]["fault_addr"],
            }
            for member in members
        ],
        "clusters": [
            {
                "key": "b9cc79c1d264303f",
                "signal": job_entry["crashes"][0]["signal"],
                "signal_name": "SIGSEGV",
                "frames": job_entry["crashes"][0]["frames"],
                "count": len(members),
                "members": members,
                "merged_from": [],
                "repro": str(repro_script),
                "minimized": {
                    "ok": True,
                    "minimized": str(minimized_file),
                    "original_size": 66,
                    "minimized_size": 41,
                },
            }
        ],
        "summary": {"crashes": len(members), "clusters": 1},
    }
    (job / "triage" / "triage.json").write_text(json.dumps(triage, ensure_ascii=False), encoding="utf-8")
    return job


def test_generate_report_schema_and_files(tmp_path):
    job = _make_job(tmp_path)
    report = generate_report(job, validate=True)
    validate_report(report)  # 显式再校验一次
    assert report["findings"], report
    finding = report["findings"][0]
    assert finding["id"].startswith("VF-")
    assert finding["severity"] == "high"
    assert finding["reproduce"]["input_sha256"]
    assert (job / "report" / "report.json").exists()
    assert (job / "report" / "report.md").exists()
    md = (job / "report" / "report.md").read_text(encoding="utf-8")
    assert "## 二、发现列表" in md
    assert "## 五、合规声明" in md
    assert "复现步骤" in md


def test_generate_report_missing_triage(tmp_path):
    job = tmp_path / "empty-job"
    job.mkdir()
    with pytest.raises(FileNotFoundError, match="triage"):
        generate_report(job)


def test_report_markdown_structure(tmp_path):
    job = _make_job(tmp_path)
    report = generate_report(job)
    md = to_markdown(report)
    assert "本报告为候选缺陷报告，须人工复核后对外提交" in md
    assert "候选缺陷" in md
    assert "CWE" in md
