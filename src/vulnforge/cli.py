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


def main() -> None:
    app()


if __name__ == "__main__":
    main()
