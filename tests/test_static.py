"""静态分析引擎测试：C / Python 规则命中、参数谓词、目录扫描。

注意：测试样本（C_SAMPLE / PY_SAMPLE）为**故意包含漏洞模式的教学代码**，
仅用于验证检测规则的正确性，不构成可利用代码。
"""

from __future__ import annotations

from pathlib import Path

from vulnforge.static.engine import load_rules, scan_file, scan_path, to_markdown

C_SAMPLE = """\
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

void copy_input(char *in) {
    char buf[64];
    strcpy(buf, in);
    printf(in);
    system(in);
}

void safe_print(const char *fmt) {
    printf("%s\\n", fmt);
}
"""

PY_SAMPLE = """\
import os
import pickle
import subprocess


def run_user(cmd):
    os.system(cmd)
    subprocess.run(cmd, shell=True)
    subprocess.run(["ls", "-la"])


def load_data(blob):
    return pickle.loads(blob)


def calc(expr):
    return eval(expr)
"""


def _rules():
    return load_rules()


def test_rules_library_wellformed():
    doc = _rules()
    assert len(doc["rules"]) >= 10
    ids = [rule["id"] for rule in doc["rules"]]
    assert len(ids) == len(set(ids))
    for rule in doc["rules"]:
        assert rule["lang"] in ("c", "python")
        assert rule["title"] and rule["match"]


def test_scan_c_sample(tmp_path):
    src = tmp_path / "vuln.c"
    src.write_text(C_SAMPLE, encoding="utf-8")
    found = scan_file(src, "c", _rules())
    hits = {(item.rule_id, item.enclosing) for item in found}
    assert ("VF-C-001", "copy_input") in hits  # strcpy
    assert ("VF-C-004", "copy_input") in hits  # system
    assert ("VF-C-005", "copy_input") in hits  # printf(in) 非字面量格式串
    # printf("%s\n", fmt) 不应命中格式化串规则
    assert not any(item.rule_id == "VF-C-005" and item.enclosing == "safe_print" for item in found)
    for item in found:
        assert item.line >= 1 and item.cwe.startswith("CWE-")


def test_scan_python_sample(tmp_path):
    src = tmp_path / "vuln.py"
    src.write_text(PY_SAMPLE, encoding="utf-8")
    found = scan_file(src, "python", _rules())
    pairs = {(item.rule_id, item.enclosing) for item in found}
    assert ("VF-P-002", "run_user") in pairs  # os.system
    assert ("VF-P-003", "run_user") in pairs  # shell=True
    assert ("VF-P-004", "load_data") in pairs  # pickle.loads
    assert ("VF-P-001", "calc") in pairs  # eval
    # 非 shell 的 subprocess.run(["ls"]) 不应命中 P-003
    assert not any(item.rule_id == "VF-P-003" and "ls" in item.evidence for item in found)


def test_scan_directory_and_markdown(tmp_path):
    (tmp_path / "a.c").write_text(C_SAMPLE, encoding="utf-8")
    (tmp_path / "b.py").write_text(PY_SAMPLE, encoding="utf-8")
    (tmp_path / "skip.txt").write_text("strcpy(1,2)", encoding="utf-8")
    candidates, files_scanned = scan_path(tmp_path, ["c", "python"], _rules())
    assert files_scanned == 2
    assert len(candidates) >= 6
    payload = {
        "target": str(tmp_path),
        "langs": ["c", "python"],
        "files_scanned": files_scanned,
        "rule_count": len(_rules()["rules"]),
        "candidates": [item.to_dict() for item in candidates],
    }
    markdown = to_markdown(payload)
    assert "静态分析候选报告" in markdown
    assert "VF-C-001" in markdown


def test_scan_skips_hidden_dirs(tmp_path):
    venv = tmp_path / ".venv"
    venv.mkdir()
    (venv / "x.py").write_text("eval('1')\n", encoding="utf-8")
    (tmp_path / "ok.py").write_text("print('hi')\n", encoding="utf-8")
    candidates, files_scanned = scan_path(Path(tmp_path), ["python"], _rules())
    assert files_scanned == 1
    assert candidates == []
