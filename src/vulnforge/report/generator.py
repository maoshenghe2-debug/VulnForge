"""CNVD 风格崩溃报告生成：triage.json + build.json + 静态扫描建议 → JSON（schema 校验）+ Markdown。

口径说明（评审 QA）：
- 报告定位为**候选缺陷报告**（automated），CWE / 严重级为建议值，需人工复核后对外提交；
- 每条发现均携带复现脚本（repro.sh，退出码 0=复现 / 1=未复现）与证据哈希（输入/崩溃文件 SHA-256）。
"""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path

from jsonschema import Draft7Validator

from .. import __version__
from ..static.engine import load_rules, scan_file
from ..triage.parse import SIGNAL_NAMES as TRIAGE_SIGNAL_NAMES

SCHEMA_PATH = Path(__file__).parent / "report.schema.json"

SIGNAL_MAP: dict[int, dict[str, str]] = {
    11: {"severity": "high", "cwe": "CWE-119", "cls": "内存损坏（越界访问 / 野指针）"},
    6: {"severity": "high", "cwe": "CWE-617", "cls": "堆检查 / 断言中断（内存管理错误）"},
    8: {"severity": "high", "cwe": "CWE-369", "cls": "算术异常（除零等）"},
    4: {"severity": "medium", "cwe": "CWE-758", "cls": "非法指令（未定义行为）"},
}
DEFAULT_SIGNAL = {"severity": "medium", "cwe": "CWE-000", "cls": "异常终止"}

DISCLAIMER = (
    "本报告由 VulnForge 自动化管线生成，仅用于**授权安全测试**（自有系统 / 开源软件审计 / 教学靶场）。"
    "所有发现均为**候选缺陷**：CWE 归类与严重级为建议值，须经安全研究人员人工复核后方可对外披露或提交（CNVD/CVE 流程）。"
)


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _lang_of(path: Path) -> str | None:
    suffix = path.suffix.lower()
    if suffix in (".c", ".h"):
        return "c"
    if suffix == ".py":
        return "python"
    return None


def validate_report(report: dict, schema_path: Path | None = None) -> None:
    """Draft-07 schema 校验；失败抛 ValueError（含前 5 条错误路径）。"""
    schema = json.loads((schema_path or SCHEMA_PATH).read_text(encoding="utf-8"))
    errors = sorted(Draft7Validator(schema).iter_errors(report), key=lambda e: list(e.path))
    if errors:
        detail = "; ".join(f"{list(err.path)}: {err.message}" for err in errors[:5])
        raise ValueError(f"报告 schema 校验失败：{detail}")


def _static_hints(source: Path, limit: int = 5) -> list[dict]:
    """对目标源码做静态扫描，提取修复建议参考（规则 CWE/建议）。"""
    lang = _lang_of(source)
    if lang is None or not source.exists():
        return []
    rules_doc = load_rules()
    hints = []
    for candidate in scan_file(source, lang, rules_doc)[:limit]:
        hints.append(
            {
                "rule_id": candidate.rule_id,
                "title": candidate.title,
                "cwe": candidate.cwe,
                "severity": candidate.severity,
                "line": candidate.line,
                "advice": candidate.advice,
            }
        )
    return hints


def _finding_from_cluster(cluster: dict, job_dir: Path, static_hints: list[dict]) -> dict:
    signal = int(cluster.get("signal", 0))
    info = SIGNAL_MAP.get(signal, DEFAULT_SIGNAL)
    frames = list(cluster.get("frames", []))
    top_frame = frames[0] if frames else "?"
    key = str(cluster.get("key", "0" * 16))
    finding_id = f"VF-{key[:8].upper()}"
    signal_name = cluster.get("signal_name") or TRIAGE_SIGNAL_NAMES.get(signal, f"SIG{signal}")

    # 复现输入：优先最小化产物
    minimized = cluster.get("minimized") or {}
    input_path = Path(minimized["minimized"]) if minimized.get("ok") else Path(cluster["members"][0])
    input_size = input_path.stat().st_size if input_path.exists() else 0
    input_sha = _sha256(input_path) if input_path.exists() else ""

    crashes = []
    for member in cluster.get("members", []):
        member_path = Path(member)
        crashes.append(
            {
                "file": member_path.name,
                "sha256": _sha256(member_path) if member_path.exists() else "",
                "signal": signal,
            }
        )

    # 修复建议：静态扫描建议 + 通用建议
    advice_lines = [f"{hint['rule_id']} · {hint['title']}（{hint['cwe']}）：{hint['advice']}" for hint in static_hints[:3]]
    remediation = "；".join(advice_lines) if advice_lines else "对输入长度 / 边界做显式校验，复核相关内存操作。"
    remediation += "。修复后建议重跑 fuzz 任务回归（vulnforge fuzz run），确认崩溃不再复现。"

    return {
        "id": finding_id,
        "title": f"{signal_name} 崩溃 · {top_frame} · {info['cls']}",
        "signal": signal,
        "signal_name": signal_name,
        "severity": info["severity"],
        "cwe_suggestion": f"{info['cwe']}（建议值，待人工复核）",
        "dedup_key": key,
        "frames": frames,
        "summary": (
            f"模糊测试在目标中触发 {signal_name}（信号 {signal}），"
            f"栈顶归一化帧为 {top_frame}；同签名崩溃 {len(cluster.get('members', []))} 个（去重后归并为 1 个唯一缺陷）。"
        ),
        "impact": (
            f"{info['cls']}：在真实调用场景下可导致进程崩溃（拒绝服务），"
            "并存在进一步利用（信息泄露 / 代码执行）的可能——须结合调用上下文人工评估。"
        ),
        "reproduce": {
            "repro_script": str(cluster.get("repro", "")),
            "input": str(input_path),
            "input_sha256": input_sha,
            "input_size": input_size,
            "exit_contract": "0=复现（目标以对应信号终止）/ 1=未复现",
            "steps": [
                f"进入任务目录：{job_dir}",
                f"执行复现脚本：bash {Path(cluster.get('repro', '')).name}（位于 repro/ 目录）",
                f"期望：输出 [复现] 目标以信号 {signal} 终止，且脚本退出码为 0",
                "如需手动验证：build/target < <最小化输入>（见任务目录 minimized/）",
            ],
        },
        "evidence": {
            "crash_count": len(cluster.get("members", [])),
            "crashes": crashes,
            "fault_addr": cluster.get("fault_addr", ""),
            "minimized": bool(minimized.get("ok")),
        },
        "remediation": remediation,
        "references": [
            "VulnForge triage 报告：triage/triage.json",
            "fuzz 任务状态：state.json（断点续跑契约）",
        ],
    }


def generate_report(job_dir: str | Path, *, validate: bool = True) -> dict:
    """生成报告：读取任务目录的 triage/build/state，输出并落盘 report/report.json + report/report.md。"""
    job_dir = Path(job_dir)
    triage_file = job_dir / "triage" / "triage.json"
    if not triage_file.exists():
        raise FileNotFoundError(f"未找到 {triage_file}（请先运行：vulnforge triage run {job_dir}）")
    triage = json.loads(triage_file.read_text(encoding="utf-8"))
    build = json.loads((job_dir / "build" / "build.json").read_text(encoding="utf-8")) if (job_dir / "build" / "build.json").exists() else {}
    state = json.loads((job_dir / "state.json").read_text(encoding="utf-8")) if (job_dir / "state.json").exists() else {}

    source = Path(build.get("target_source", ""))
    hints = _static_hints(source) if build else []
    findings = [_finding_from_cluster(cluster, job_dir, hints) for cluster in triage.get("clusters", [])]

    job_meta = state.get("job", {})
    stats = state.get("stats", {})
    report = {
        "schema_version": 1,
        "tool": "vulnforge",
        "tool_version": __version__,
        "generated_at": datetime.now(UTC).isoformat(timespec="seconds"),
        "job_id": job_dir.name,
        "target": {
            "source": build.get("target_source", ""),
            "binary_sha256": build.get("sha256", ""),
            "compiler": build.get("compiler", ""),
            "flags": build.get("flags", []),
            "environment": build.get("environment", ""),
        },
        "fuzzing": {
            "cores": int(job_meta.get("cores", 0)),
            "duration_s": int(job_meta.get("duration_s", 0)),
            "execs_total": int(stats.get("execs_total", 0)),
            "crashes_total": int(stats.get("crashes_total", 0)),
            "unique_defects": len(findings),
        },
        "static_hints": hints,
        "findings": findings,
        "disclaimer": DISCLAIMER,
    }
    if validate:
        validate_report(report)

    report_dir = job_dir / "report"
    report_dir.mkdir(exist_ok=True)
    (report_dir / "report.json").write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    (report_dir / "report.md").write_text(to_markdown(report), encoding="utf-8")
    return report


def to_markdown(report: dict) -> str:
    """渲染 CNVD 风格 Markdown 报告。"""
    target = report["target"]
    fuzzing = report["fuzzing"]
    lines = [
        f"# VulnForge 崩溃报告 · {report.get('job_id', '')}",
        "",
        f"> 生成时间：{report['generated_at']} ｜ 工具：vulnforge v{report['tool_version']} ｜ "
        "本报告为候选缺陷报告，须人工复核后对外提交。",
        "",
        "## 一、目标与测试概况",
        "",
        f"- 源码：`{target.get('source', '')}`",
        f"- 二进制 SHA-256：`{target.get('binary_sha256', '')}`（{target.get('environment', '')}，{target.get('compiler', '')}）",
        f"- 模糊测试：{fuzzing['cores']} 核 × {fuzzing['duration_s']}s ｜ 累计执行 {fuzzing['execs_total']} 次 ｜ "
        f"收集崩溃 {fuzzing['crashes_total']} 个 → 唯一缺陷 {fuzzing['unique_defects']} 个",
        "",
        "## 二、发现列表",
        "",
        "| # | 编号 | 标题 | 信号 | 危险级 | CWE（建议） | 同签名崩溃 |",
        "|---|---|---|---|---|---|---|",
    ]
    for idx, finding in enumerate(report["findings"], start=1):
        lines.append(
            f"| {idx} | {finding['id']} | {finding['title']} | {finding['signal_name']} | "
            f"{finding['severity']} | {finding['cwe_suggestion']} | {finding['evidence']['crash_count']} |"
        )
    if not report["findings"]:
        lines.append("| — | — | 未发现崩溃（按当前规则与时长） | — | — | — | — |")

    lines += ["", "## 三、缺陷详情", ""]
    for idx, finding in enumerate(report["findings"], start=1):
        reproduce = finding["reproduce"]
        evidence = finding["evidence"]
        lines += [
            f"### 3.{idx} [{finding['id']}] {finding['title']}",
            "",
            f"- **信号**：{finding['signal_name']}（{finding['signal']}） ｜ **危险级（建议）**：{finding['severity']} ｜ "
            f"**CWE（建议）**：{finding['cwe_suggestion']}",
            f"- **栈帧（归一化）**：{' ← '.join(finding['frames'][:5]) or '?'}",
            f"- **概述**：{finding['summary']}",
            f"- **影响**：{finding['impact']}",
            "- **复现步骤**：",
        ]
        for step_idx, step in enumerate(reproduce["steps"], start=1):
            lines.append(f"  {step_idx}. {step}")
        lines += [
            f"- **证据**：输入 SHA-256 `{reproduce['input_sha256']}`（{reproduce['input_size']} 字节，"
            f"{'已最小化' if evidence.get('minimized') else '原始'}）",
            f"  - 崩溃文件（{evidence['crash_count']}）：" + "、".join(item["file"] for item in evidence["crashes"]),
            f"- **修复建议**：{finding['remediation']}",
            "",
        ]

    if report.get("static_hints"):
        lines += ["## 四、静态扫描修复参考", ""]
        for hint in report["static_hints"]:
            lines.append(f"- `{hint['rule_id']}` {hint['title']}（{hint['cwe']}，第 {hint.get('line', '?')} 行）：{hint.get('advice', '')}")
        lines.append("")

    lines += [
        "## 五、合规声明",
        "",
        report["disclaimer"],
        "",
    ]
    return "\n".join(lines)
