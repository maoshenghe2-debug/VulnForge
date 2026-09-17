"""vulnforge.static：基于 tree-sitter 的轻量静态候选扫描（C / Python）。

设计（v1.0 冻结）：
- 规则 YAML 驱动（``rules_data.yaml``，可扩展，**新增规则无需改代码**）；
- 匹配语义：``call_any``（函数调用）/ ``chain_any``（点链调用，如 os.system）/
  ``arg_not_literal``（指定参数非字面量，如 printf(fmt)）/ ``kwarg_true``（如 shell=True）；
- 输出候选项：文件:行:列 + 所在函数 + 规则 + 证据行 + 建议；
- 定位：AST 结构匹配（优于纯文本扫描的误报控制），供 fuzz 目标选型与人工复核。

限制：v1.0 为**单文件分析**（不含跨文件调用链）；误报属预期，需人工复核。
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from pathlib import Path

import yaml
from tree_sitter_language_pack import get_parser

RULES_PATH = Path(__file__).parent / "rules_data.yaml"

LANG_EXT: dict[str, set[str]] = {
    "c": {".c", ".h"},
    "python": {".py"},
}

_SKIP_DIRS = {
    ".git",
    ".hg",
    ".svn",
    ".venv",
    "venv",
    "node_modules",
    "__pycache__",
    "dist",
    "build",
    ".vulnforge",
    ".ruff_cache",
    ".pytest_cache",
}

_SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2}


@dataclass
class Candidate:
    file: str
    line: int
    column: int
    rule_id: str
    title: str
    severity: str
    cwe: str
    enclosing: str
    evidence: str
    advice: str

    def to_dict(self) -> dict:
        return asdict(self)


def load_rules(path: Path | None = None) -> dict:
    """加载规则库 YAML（默认内置规则集）。"""
    with open(path or RULES_PATH, encoding="utf-8") as fh:
        data = yaml.safe_load(fh)
    if not isinstance(data, dict) or not isinstance(data.get("rules"), list):
        raise ValueError("规则库格式错误：缺少 rules 列表")
    for rule in data["rules"]:
        missing = {"id", "lang", "title", "match"} - set(rule)
        if missing:
            raise ValueError(f"规则 {rule.get('id', '?')} 缺少字段：{sorted(missing)}")
    return data


# ------------------------------------------------------------------ 内部工具


def _text(node, src: bytes) -> str:
    return src[node.start_byte : node.end_byte].decode("utf-8", errors="replace")


def _string_types(lang: str) -> set[str]:
    return {"string_literal", "concatenated_string"} if lang == "c" else {"string"}


def _function_name(fn_node, src: bytes) -> str:
    name = fn_node.child_by_field_name("name")
    if name is not None:
        return _text(name, src)
    decl = fn_node.child_by_field_name("declarator")
    hops = 0
    while decl is not None and hops < 8:
        if decl.type == "identifier":
            return _text(decl, src)
        nxt = decl.child_by_field_name("declarator")
        if nxt is None:
            for child in decl.children:
                if child.type == "identifier":
                    return _text(child, src)
            break
        decl = nxt
        hops += 1
    return "<unknown>"


def _enclosing_function(node, src: bytes) -> str:
    cur = node.parent
    while cur is not None:
        if cur.type == "function_definition":
            return _function_name(cur, src)
        cur = cur.parent
    return "<global>"


def _argument_nodes(node) -> list:
    args = node.child_by_field_name("arguments")
    if args is None:
        return []
    return [child for child in args.children if child.is_named]


def _has_kwarg_true(node, key_name: str, src: bytes) -> bool:
    args = node.child_by_field_name("arguments")
    if args is None:
        return False
    for child in args.children:
        if child.type != "keyword_argument":
            continue
        key = child.child_by_field_name("name")
        value = child.child_by_field_name("value")
        if key is not None and _text(key, src) == key_name and value is not None and _text(value, src) in ("True", "true"):
            return True
    return False


def _match_rule(node, lang: str, rule: dict, src: bytes) -> bool:
    call_type = "call_expression" if lang == "c" else "call"
    if node.type != call_type:
        return False
    fn = node.child_by_field_name("function")
    if fn is None:
        return False
    name = _text(fn, src)
    match = rule["match"]

    names = match.get("call_any") or match.get("chain_any")
    if not names or name not in names:
        return False

    if "arg_not_literal" in match:
        args = _argument_nodes(node)
        idx = int(match["arg_not_literal"])
        if idx >= len(args):
            return False
        if args[idx].type in _string_types(lang):
            return False

    return "kwarg_true" not in match or _has_kwarg_true(node, str(match["kwarg_true"]), src)


# ------------------------------------------------------------------ 扫描


def scan_file(path: Path, lang: str, rules_doc: dict) -> list[Candidate]:
    """扫描单个源码文件，返回候选项列表。"""
    src = path.read_bytes()
    parser = get_parser(lang)
    tree = parser.parse(src)
    text = src.decode("utf-8", errors="replace")
    lines = text.splitlines()
    rules = [rule for rule in rules_doc["rules"] if rule.get("lang") == lang]

    results: list[Candidate] = []
    stack = [tree.root_node]
    while stack:
        node = stack.pop()
        for rule in rules:
            if _match_rule(node, lang, rule, src):
                row, col = node.start_point
                evidence = lines[row].strip()[:160].replace("|", "¦") if row < len(lines) else ""
                results.append(
                    Candidate(
                        file=str(path),
                        line=row + 1,
                        column=col + 1,
                        rule_id=rule["id"],
                        title=rule["title"],
                        severity=str(rule.get("severity", "medium")),
                        cwe=str(rule.get("cwe", "")),
                        enclosing=_enclosing_function(node, src),
                        evidence=evidence,
                        advice=str(rule.get("advice", "")),
                    )
                )
        stack.extend(node.named_children)
    return results


def scan_path(root: Path, langs: list[str], rules_doc: dict) -> tuple[list[Candidate], int]:
    """扫描文件或目录。返回（候选项列表, 扫描文件数）。"""
    exts: set[str] = set()
    for lang in langs:
        exts |= LANG_EXT.get(lang, set())

    if root.is_file():
        targets = [root]
    else:
        targets = [
            path
            for path in sorted(root.rglob("*"))
            if path.is_file() and path.suffix in exts and not any(part in _SKIP_DIRS for part in path.parts)
        ]

    candidates: list[Candidate] = []
    files_scanned = 0
    lang_of = {ext: lang for lang, extset in LANG_EXT.items() for ext in extset}
    for path in targets:
        lang = lang_of.get(path.suffix)
        if lang is None or lang not in langs:
            continue
        candidates.extend(scan_file(path, lang, rules_doc))
        files_scanned += 1

    candidates.sort(key=lambda c: (_SEVERITY_ORDER.get(c.severity, 9), c.file, c.line))
    return candidates, files_scanned


# ------------------------------------------------------------------ 导出


def to_markdown(payload: dict) -> str:
    """生成 Markdown 候选报告。"""
    rows = [
        "# 静态分析候选报告",
        "",
        f"- 目标：`{payload['target']}`",
        f"- 语言：{', '.join(payload['langs'])} ｜ 文件 {payload['files_scanned']} 个 ｜ "
        f"规则 {payload['rule_count']} 条 ｜ 候选 {len(payload['candidates'])} 处",
        "",
        "| 严重级 | 规则 | 位置 | 所在函数 | CWE | 证据（截断） |",
        "|---|---|---|---|---|---|",
    ]
    for item in payload["candidates"]:
        rows.append(
            f"| {item['severity']} | {item['rule_id']} {item['title']} | `{item['file']}:{item['line']}` | "
            f"{item['enclosing']} | {item['cwe']} | `{item['evidence']}` |"
        )
    if not payload["candidates"]:
        rows.append("| — | — | — | — | — | — |")
    rows.append("")
    return "\n".join(rows)
