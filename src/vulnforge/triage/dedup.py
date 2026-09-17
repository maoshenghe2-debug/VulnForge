"""崩溃去重：``dedup_key = sha256(signal | top5 归一化帧 | fault_addr>>12)``（冻结契约）。"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field


def dedup_key(signal: int, frames: list[str], fault_addr: int, top: int = 5) -> str:
    """计算去重键：信号 + 栈顶 5 帧（归一化）+ 故障地址页号（>>12）。"""
    payload = f"{signal}|{'/'.join(frames[:top])}|{fault_addr >> 12}"
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:16]


@dataclass
class Cluster:
    key: str
    signal: int
    frames: list[str]
    members: list[str] = field(default_factory=list)


def cluster_crashes(entries: list[dict]) -> list[Cluster]:
    """聚类：``entries`` 元素含 ``file / signal / frames / fault_addr``；保序输出。"""
    clusters: dict[str, Cluster] = {}
    for item in entries:
        key = dedup_key(item["signal"], item["frames"], item["fault_addr"])
        cluster = clusters.get(key)
        if cluster is None:
            cluster = Cluster(key=key, signal=item["signal"], frames=list(item["frames"]))
            clusters[key] = cluster
        cluster.members.append(item["file"])
    return list(clusters.values())
