"""vulnforge demo：单链路演示（静态扫描 → fuzz → 崩溃分类 → 报告），设计时长 ≤10 分钟。

默认栈溢出样本 + 20s × 2 核：约 1–2 分钟完成，输出四阶段摘要与报告路径。
"""

from __future__ import annotations

import time
from collections.abc import Callable
from pathlib import Path

from .fuzz.orchestrator import run_job
from .report.generator import generate_report
from .static.engine import load_rules, scan_file
from .triage.pipeline import run_triage

SAMPLES_DIR = Path(__file__).parent / "range" / "samples"
SEEDS_DIR = Path(__file__).parent / "range" / "seeds"


def run_demo(
    sample: str = "stack_overflow",
    *,
    duration_s: int = 20,
    cores: int = 2,
    workspace: str | Path = ".vulnforge",
    progress: Callable[[str, str], None] | None = None,
) -> dict:
    """执行演示单链路，返回各阶段结果摘要。

    ``progress``：可选回调 ``progress(step, detail)``，用于 CLI 逐步展示。
    """

    def _p(step: str, detail: str = "") -> None:
        if progress is not None:
            progress(step, detail)

    t0 = time.time()
    sample_src = SAMPLES_DIR / f"{sample}.c"
    if not sample_src.exists():
        available = ", ".join(sorted(item.stem for item in SAMPLES_DIR.glob("*.c")))
        raise FileNotFoundError(f"样本不存在：{sample}（可选：{available}）")

    # ① 静态扫描
    _p("静态扫描", str(sample_src))
    rules_doc = load_rules()
    candidates = scan_file(sample_src, "c", rules_doc)
    static_summary = {"count": len(candidates), "rules": sorted({item.rule_id for item in candidates})}
    _p("静态完成", f"{static_summary['count']} 处候选（{', '.join(static_summary['rules']) or '无'}）")

    # ② fuzz
    seeds = SEEDS_DIR / sample
    _p("模糊测试", f"{cores} 核 × {duration_s}s")
    state = run_job(
        sample_src,
        name=f"demo-{sample}",
        cores=cores,
        duration_s=duration_s,
        seeds=seeds if seeds.is_dir() else None,
        workspace=workspace,
    )
    job_dir = Path(state["artifacts"]["job_dir"])
    _p("fuzz 完成", f"执行 {state['stats']['execs_total']} 次，崩溃 {state['stats']['crashes_total']} 个")

    # ③ 崩溃分类
    _p("崩溃分类", "gdb 归一化 + 去重 + 最小化")
    triage = run_triage(job_dir, minimize=True)
    if not triage.get("ok"):
        _p("分类终止", triage.get("error", ""))
        return {
            "static": static_summary,
            "fuzz": state,
            "triage": triage,
            "report": None,
            "job_dir": str(job_dir),
            "elapsed_s": round(time.time() - t0, 1),
        }
    _p("分类完成", f"{triage['summary']['crashes']} 崩溃 → {triage['summary']['clusters']} 个唯一缺陷")

    # ④ 报告
    _p("报告生成", "schema 校验 + Markdown 渲染")
    report = generate_report(job_dir)
    _p("报告完成", str(job_dir / "report" / "report.md"))

    return {
        "static": static_summary,
        "fuzz": state,
        "triage": triage,
        "report": report,
        "job_dir": str(job_dir),
        "elapsed_s": round(time.time() - t0, 1),
    }
