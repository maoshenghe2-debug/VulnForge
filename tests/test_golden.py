"""golden 标注集 pairwise F1 基准（≥0.95 契约，docs/08 §4）。

数据：6 个靶场样本的真实 fuzz 崩溃（gdb bt16 归一化帧），label = 样本（真实缺陷）。
判定：按任务内聚类（含 R1/R2 合并），pairwise precision / recall / F1。
本测试不依赖 WSL/AFL（纯数据驱动，CI 可跑）。
"""

from __future__ import annotations

import json
from pathlib import Path

from vulnforge.triage.dedup import cluster_crashes

GOLDEN_PATH = Path(__file__).parent / "golden" / "golden_crashes.json"
F1_THRESHOLD = 0.95


def _load_golden() -> dict:
    assert GOLDEN_PATH.exists(), f"缺少 golden 标注集：{GOLDEN_PATH}"
    return json.loads(GOLDEN_PATH.read_text(encoding="utf-8"))


def _predict(golden: dict) -> dict[tuple[str, str], tuple[str, str]]:
    pred: dict[tuple[str, str], tuple[str, str]] = {}
    for job_entry in golden["jobs"]:
        label = job_entry["label"]
        entries = [
            {
                "file": crash["file"],
                "signal": crash["signal"],
                "frames": crash["frames"],
                "fault_addr": crash["fault_addr"],
            }
            for crash in job_entry["crashes"]
        ]
        for cluster in cluster_crashes(entries):
            for member in cluster.members:
                pred[(label, member)] = (label, cluster.key)
    return pred


def test_golden_pairwise_f1_meets_threshold():
    golden = _load_golden()
    pred = _predict(golden)
    rows = list(pred.keys())
    assert len(rows) == sum(len(job["crashes"]) for job in golden["jobs"])
    tp = fn = fp = 0
    for i in range(len(rows)):
        for j in range(i + 1, len(rows)):
            a, b = rows[i], rows[j]
            same_label = a[0] == b[0]
            same_pred = pred[a] == pred[b]
            if same_label and same_pred:
                tp += 1
            elif same_label:
                fn += 1
            elif same_pred:
                fp += 1
    precision = tp / (tp + fp) if tp + fp else 1.0
    recall = tp / (tp + fn) if tp + fn else 1.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    assert f1 >= F1_THRESHOLD, f"pairwise F1={f1:.3f} < {F1_THRESHOLD}（TP={tp} FN={fn} FP={fp}）"


def test_golden_dataset_shape():
    golden = _load_golden()
    labels = [job["label"] for job in golden["jobs"]]
    assert len(labels) == 6
    assert len(set(labels)) == 6
    total = sum(len(job["crashes"]) for job in golden["jobs"])
    assert total >= 10
    for job in golden["jobs"]:
        assert job["crashes"], job["label"]
        for crash in job["crashes"]:
            assert crash["frames"], crash
            assert crash["signal"] > 0
