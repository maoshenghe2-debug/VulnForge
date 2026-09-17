"""doctor 环境自检测试（检查项完整性 / Python 检查逻辑 / 工作目录检查）。"""

from __future__ import annotations

import pytest

from vulnforge.doctor import STATUS_OK, check_workdir, run_doctor

EXPECTED_KEYS = {"python", "wsl", "git", "aflpp", "afl_clang", "gdb", "tree_sitter", "disk", "workdir"}


@pytest.fixture(scope="module")
def doctor_report():
    """整模块共享一次 run_doctor（Windows 下含 WSL 探测，较重）。"""
    return run_doctor()


def test_doctor_returns_all_checks(doctor_report):
    keys = {item["key"] for item in doctor_report["checks"]}
    assert len(doctor_report["checks"]) >= 8
    assert keys >= EXPECTED_KEYS
    assert doctor_report["summary"]["ok"] >= 1
    assert doctor_report["exit_code"] in (0, 1, 3)


def test_python_check_logic(doctor_report):
    python_check = next(item for item in doctor_report["checks"] if item["key"] == "python")
    assert python_check["status"] == STATUS_OK  # requires-python ≥3.11
    assert python_check["required"] is True


def test_decode_strips_ansi_and_nulls():
    """子进程输出解码：剥离 ANSI 转义序列与空字节（工具彩色输出 / wsl.exe 混排）。"""
    from vulnforge.wsl import decode

    assert decode(b"\x1b[0;36mafl-fuzz++4.09c\x1b[0m based on afl") == "afl-fuzz++4.09c based on afl"
    assert decode(b"U\x00b\x00u\x00n\x00t\x00u\x00") == "Ubuntu"
    assert decode(b"") == ""


def test_workdir_check_creates_dir(tmp_path):
    check = check_workdir(tmp_path)
    assert check.status == STATUS_OK
    assert (tmp_path / ".vulnforge").is_dir()
