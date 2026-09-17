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


def main() -> None:
    app()


if __name__ == "__main__":
    main()
