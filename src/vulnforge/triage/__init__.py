"""vulnforge.triage：崩溃解析 / 去重 / 最小化 / 复现脚本。"""

from .dedup import Cluster, cluster_crashes, dedup_key
from .gdb import GdbInfo, analyze_crash, normalize_frames
from .minimize import minimize_crash
from .parse import CrashMeta, list_crashes, parse_crash
from .pipeline import run_triage

__all__ = [
    "Cluster",
    "CrashMeta",
    "GdbInfo",
    "analyze_crash",
    "cluster_crashes",
    "dedup_key",
    "list_crashes",
    "minimize_crash",
    "normalize_frames",
    "parse_crash",
    "run_triage",
]
