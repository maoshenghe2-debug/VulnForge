"""VulnForge CLI 入口（vulnforge doctor | static | fuzz | triage | report | range | demo）。"""

from __future__ import annotations

import json as jsonlib
import sys

import typer
from rich.console import Console
from rich.table import Table

from . import __version__
from .doctor import STATUS_FAIL, STATUS_OK, STATUS_WARN, run_doctor

if sys.stdout is not None and hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")
if sys.stderr is not None and hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8")

app = typer.Typer(
    name="vulnforge",
    help="VulnForge · 智能漏洞挖掘工作台（静态分析 → 模糊测试 → 崩溃分析 → 报告闭环）",
    no_args_is_help=True,
)
console = Console()

_STATUS_STYLE = {
    STATUS_OK: "[green]就绪[/green]",
    STATUS_WARN: "[yellow]缺失[/yellow]",
    STATUS_FAIL: "[red]不满足[/red]",
}


@app.callback()
def _root() -> None:
    """VulnForge CLI。"""


@app.command()
def doctor(
    as_json: bool = typer.Option(False, "--json", help="以 JSON 输出（供 CI / 脚本消费）"),
) -> None:
    """环境自检：9 项检查 + 一键修复命令（Windows 下经 WSL2 探测）。"""
    report = run_doctor()
    if as_json:
        console.print_json(jsonlib.dumps(report, ensure_ascii=False))
    else:
        table = Table(title=f"VulnForge 环境自检 · v{__version__} · {report['platform']}")
        table.add_column("检查项", style="cyan", no_wrap=True)
        table.add_column("状态", no_wrap=True)
        table.add_column("详情", overflow="fold")
        table.add_column("修复命令", style="dim", overflow="fold")
        for item in report["checks"]:
            table.add_row(item["name"], _STATUS_STYLE[item["status"]], item["detail"], item["fix"])
        console.print(table)
        summary = report["summary"]
        console.print(
            f"就绪 {summary['ok']} · 缺失 {summary['warn']} · 不满足 {summary['fail']} → 退出码 {report['exit_code']}"
        )
    raise typer.Exit(code=report["exit_code"])


static_app = typer.Typer(help="静态分析（tree-sitter + YAML 规则；C / Python）", no_args_is_help=True)
app.add_typer(static_app, name="static")


@static_app.command("scan")
def static_scan(
    path: str = typer.Argument(..., help="源码文件或目录路径"),
    lang: str = typer.Option("c,python", "--lang", help="语言集合（逗号分隔：c,python）"),
    as_json: bool = typer.Option(False, "--json", help="以 JSON 输出"),
    out: str = typer.Option(None, "-o", "--out", help="结果导出路径（.json / .md）"),
) -> None:
    """静态候选扫描：输出「位置 + 所在函数 + 规则 + 证据」候选清单（供 fuzz 选型）。"""
    from pathlib import Path as _Path

    from .static.engine import load_rules, scan_path, to_markdown

    langs = [item.strip().lower() for item in lang.split(",") if item.strip()]
    target = _Path(path)
    if not target.exists():
        console.print(f"[red]路径不存在：{path}[/red]")
        raise typer.Exit(code=2)

    rules_doc = load_rules()
    candidates, files_scanned = scan_path(target, langs, rules_doc)
    payload = {
        "tool": "vulnforge",
        "version": __version__,
        "target": str(target),
        "langs": langs,
        "files_scanned": files_scanned,
        "rule_count": len(rules_doc["rules"]),
        "candidates": [item.to_dict() for item in candidates],
    }

    if out:
        out_path = _Path(out)
        if out_path.suffix == ".json":
            out_path.write_text(jsonlib.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
        else:
            out_path.write_text(to_markdown(payload), encoding="utf-8")
        console.print(f"已导出：[bold]{out_path}[/bold]")

    if as_json:
        console.print_json(jsonlib.dumps(payload, ensure_ascii=False))
        return

    table = Table(title=f"静态候选 · {target} · {files_scanned} 个文件 · {len(candidates)} 处候选")
    table.add_column("严重级", no_wrap=True)
    table.add_column("规则", no_wrap=True)
    table.add_column("位置", no_wrap=True)
    table.add_column("所在函数", no_wrap=True)
    table.add_column("证据", overflow="fold")
    style = {"high": "red", "medium": "yellow", "low": "cyan"}
    for item in candidates:
        table.add_row(
            f"[{style.get(item.severity, 'white')}]{item.severity}[/]",
            item.rule_id,
            f"{_Path(item.file).name}:{item.line}",
            item.enclosing,
            item.evidence,
        )
    console.print(table)
    if not candidates:
        console.print("[green]未发现候选（按当前规则集）[/green]")


fuzz_app = typer.Typer(help="模糊测试编排（AFL++ / WSL2 或 Linux）", no_args_is_help=True)
app.add_typer(fuzz_app, name="fuzz")


def _parse_duration(text: str) -> int:
    """解析时长：60 / 30s / 10m / 2h → 秒。"""
    t = text.strip().lower()
    try:
        if t.endswith("h"):
            return int(float(t[:-1]) * 3600)
        if t.endswith("m"):
            return int(float(t[:-1]) * 60)
        if t.endswith("s"):
            return int(float(t[:-1]))
        return int(float(t))
    except ValueError as exc:
        raise typer.BadParameter(f"无法解析时长：{text}（示例：60 / 30s / 10m / 2h）") from exc


@fuzz_app.command("run")
def fuzz_run(
    target: str = typer.Argument(..., help="目标源码（.c；需实现 vuln_entry，或自带 main 兼容 harness）"),
    name: str = typer.Option(None, "--name", help="任务名（默认取文件名）"),
    cores: int = typer.Option(4, "--cores", min=1, max=32, help="并行核数"),
    duration: str = typer.Option("60", "--duration", help="时长：秒 / 30s / 10m / 2h"),
    seeds: str = typer.Option(None, "--seeds", help="种子语料目录（缺省内置最小种子）"),
    workspace: str = typer.Option(".vulnforge", "--workspace", help="工作区目录"),
    resume: str = typer.Option(None, "--resume", help="续跑：既有任务目录（使用 -i- 恢复）"),
) -> None:
    """启动 fuzz 任务（阻塞至结束）：构建 → 语料 → 多核运行 → 收集崩溃。"""
    from .fuzz.orchestrator import run_job

    duration_s = _parse_duration(duration)
    try:
        state = run_job(
            target,
            name=name,
            cores=cores,
            duration_s=duration_s,
            seeds=seeds,
            resume=resume,
            workspace=workspace,
        )
    except FileNotFoundError as exc:
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(code=2) from exc

    job_status = state["job"]["status"]
    stats = state["stats"]
    crashes = state["artifacts"].get("crash_files", [])
    table = Table(title=f"fuzz 任务 · {state['job']['id']} · {job_status}")
    table.add_column("实例", no_wrap=True)
    table.add_column("执行数", justify="right")
    table.add_column("exec/s", justify="right")
    table.add_column("崩溃", justify="right")
    for worker in state["workers"]:
        table.add_row(worker["name"], str(worker["execs_done"]), f"{worker['execs_per_sec']:.0f}", str(worker["crashes"]))
    console.print(table)
    console.print(
        f"总计：执行 {stats['execs_total']} · {stats['execs_per_sec']} exec/s · 崩溃 {stats['crashes_total']}（去重前）"
    )
    if crashes:
        console.print(f"崩溃文件（{len(crashes)}）：")
        for item in crashes[:10]:
            console.print(f"  [yellow]{item}[/yellow]")
    console.print(f"任务目录：[bold]{state['artifacts']['job_dir']}[/bold]（state.json 契约 / 可 --resume 续跑）")
    if job_status == "failed":
        console.print("[red]构建失败：查看任务目录 build/build.json 的 output_tail[/red]")
        raise typer.Exit(code=3)
    if job_status == "timeout":
        raise typer.Exit(code=4)


@fuzz_app.command("status")
def fuzz_status(job: str = typer.Argument(..., help="任务目录（含 state.json）")) -> None:
    """查看任务状态（读取 state.json 契约）。"""
    from pathlib import Path as _Path

    state_file = _Path(job) / "state.json" if _Path(job).is_dir() else _Path(job)
    if not state_file.exists():
        console.print(f"[red]未找到 state.json：{state_file}[/red]")
        raise typer.Exit(code=2)
    console.print_json(state_file.read_text(encoding="utf-8"))


@fuzz_app.command("stop")
def fuzz_stop(job: str = typer.Argument(..., help="任务目录")) -> None:
    """请求优雅停止（写 STOP 标记，由运行的 run.sh 处理）。"""
    from .fuzz.orchestrator import request_stop

    if not request_stop(job):
        console.print(f"[red]任务目录不存在：{job}[/red]")
        raise typer.Exit(code=2)
    console.print(f"已写入 STOP：{job}（运行中的任务将优雅退出）")


triage_app = typer.Typer(help="崩溃分类：gdb 归一化 / 去重 / 最小化 / repro 脚本", no_args_is_help=True)
app.add_typer(triage_app, name="triage")


@triage_app.command("run")
def triage_run(
    job: str = typer.Argument(..., help="fuzz 任务目录（含 crashes/ 与 build/）"),
    minimize: bool = typer.Option(True, "--minimize/--no-minimize", help="是否用 afl-tmin 最小化"),
    limit: int = typer.Option(None, "--limit", help="最多处理多少个崩溃文件"),
) -> None:
    """崩溃分类流水线：gdb 分析 → dedup_key 去重 → 最小化 → repro.sh（0=复现/1=未复现）。"""
    from pathlib import Path as _Path

    from .triage.pipeline import run_triage

    job_path = _Path(job)
    if not (job_path / "crashes").is_dir():
        console.print(f"[red]未找到崩溃目录：{job_path / 'crashes'}[/red]")
        raise typer.Exit(code=2)

    console.print(f"分析中：{job_path}（gdb 归一化 + afl-tmin{' 最小化' if minimize else ' 已跳过'}）…")
    result = run_triage(job_path, minimize=minimize, limit=limit)
    if not result.get("ok"):
        console.print(f"[red]{result.get('error')}[/red]")
        raise typer.Exit(code=4)

    table = Table(
        title=f"崩溃分类 · {result['summary']['crashes']} 崩溃 → {result['summary']['clusters']} 个唯一缺陷"
    )
    table.add_column("去重键", no_wrap=True)
    table.add_column("信号", no_wrap=True)
    table.add_column("数量", justify="right")
    table.add_column("栈顶（归一化）", overflow="fold")
    table.add_column("最小化", overflow="fold")
    for cluster in result["clusters"]:
        minfo = cluster.get("minimized") or {}
        min_txt = f"{minfo.get('original_size')} → {minfo.get('minimized_size')} 字节" if minfo.get("ok") else "（跳过）"
        table.add_row(
            cluster["key"],
            str(cluster["signal"]),
            str(cluster["count"]),
            " ← ".join(cluster["frames"][:3]) or "?",
            min_txt,
        )
    console.print(table)
    for cluster in result["clusters"]:
        console.print(f"  [{cluster['key']}] repro: [bold]{cluster['repro']}[/bold]")
    console.print(f"报告：[bold]{result['job_dir']}/triage/triage.json[/bold]")


@app.command()
def report(
    job: str = typer.Argument(..., help="fuzz 任务目录（须先完成 triage）"),
    as_json: bool = typer.Option(False, "--json", help="以 JSON 输出完整报告"),
) -> None:
    """生成 CNVD 风格崩溃报告（schema 校验 → report/report.json + report/report.md）。"""
    from .report.generator import generate_report

    try:
        rep = generate_report(job)
    except FileNotFoundError as exc:
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(code=2) from exc
    except ValueError as exc:
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(code=4) from exc

    if as_json:
        console.print_json(jsonlib.dumps(rep, ensure_ascii=False))
        return

    table = Table(title=f"崩溃报告 · {rep['job_id']} · {rep['fuzzing']['unique_defects']} 个唯一缺陷")
    table.add_column("编号", no_wrap=True)
    table.add_column("标题", overflow="fold")
    table.add_column("危险级", no_wrap=True)
    table.add_column("CWE（建议）", no_wrap=True)
    for finding in rep["findings"]:
        table.add_row(finding["id"], finding["title"], finding["severity"], finding["cwe_suggestion"])
    console.print(table)
    console.print(f"报告：[bold]{job}/report/report.md[/bold]（JSON 见 report/report.json，已通过 schema 校验）")
    console.print(f"复现入口：bash {job}/repro/<去重键>.sh（退出码 0=复现 / 1=未复现）")


@app.command()
def demo(
    sample: str = typer.Option("stack_overflow", "--sample", help="靶场样本名（range/samples/*.c）"),
    duration: str = typer.Option("20", "--duration", help="fuzz 时长（秒 / 30s / 1m）"),
    cores: int = typer.Option(2, "--cores", min=1, max=32, help="并行核数"),
    workspace: str = typer.Option(".vulnforge", "--workspace", help="工作区目录"),
) -> None:
    """单链路演示（≤10 分钟）：静态扫描 → fuzz → 崩溃分类 → 报告。"""
    from .demo import run_demo

    duration_s = _parse_duration(duration)

    def progress(step: str, detail: str = "") -> None:
        console.print(f"  [cyan]▶[/cyan] {step}" + (f"：{detail}" if detail else ""))

    console.print(f"[bold]VulnForge demo[/bold] · 样本 {sample} · {cores} 核 × {duration_s}s")
    try:
        result = run_demo(sample, duration_s=duration_s, cores=cores, workspace=workspace, progress=progress)
    except FileNotFoundError as exc:
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(code=2) from exc

    triage = result["triage"]
    if not triage.get("ok"):
        console.print(f"[yellow]未发现崩溃：{triage.get('error', '')}[/yellow]（可加大 --duration 重试）")
        raise typer.Exit(code=4)
    console.print(
        f"✅ 完成（{result['elapsed_s']}s）：静态 {result['static']['count']} 处候选 → "
        f"fuzz {result['fuzz']['stats']['execs_total']} 次 → "
        f"{triage['summary']['crashes']} 崩溃 → {triage['summary']['clusters']} 个唯一缺陷 → "
        f"报告 [bold]{result['job_dir']}/report/report.md[/bold]"
    )


def main() -> None:
    app()


if __name__ == "__main__":
    main()
