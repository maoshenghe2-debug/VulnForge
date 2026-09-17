"""崩溃去重与聚类。

- 精确签名（冻结契约）：``dedup_key = sha256(signal | top5 归一化帧 | fault_addr>>12)``；
- 聚类合并（v0.1 增强，依据 golden 基准实测）——**仅在单任务（同一二进制）内生效**，
  跨目标精度不受影响：
  - R2：共享同一 ``vuln_entry:<行号>`` 源帧的簇合并（同源多形态，如 `%n` 写中断与
    `%ls` 转换中断）；
  - R1：归因弱簇（栈帧全为 ``??``，野跳转等无符号信息）并入同信号最强簇。
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field

SOURCE_FRAME_RE = re.compile(r"^vuln_entry:\d+$")


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
    merged_from: list[str] = field(default_factory=list)


def _is_attribution_weak(cluster: Cluster) -> bool:
    """栈帧全为 ``??``（无任何符号信息）视为归因弱簇。"""
    return all(frame == "??" for frame in cluster.frames) if cluster.frames else True


def _source_lines(cluster: Cluster) -> set[str]:
    return {frame for frame in cluster.frames if SOURCE_FRAME_RE.match(frame)}


def _absorb(target: Cluster, other: Cluster) -> None:
    target.members.extend(other.members)
    target.merged_from.append(other.key)
    target.merged_from.extend(other.merged_from)


def merge_clusters(clusters: list[Cluster]) -> list[Cluster]:
    """R2（同源帧）+ R1（弱簇归并）合并，保序输出。"""
    result: list[Cluster] = []
    for cluster in clusters:
        lines = _source_lines(cluster)
        target = None
        if lines:
            target = next((item for item in result if lines & _source_lines(item)), None)
        if target is None:
            result.append(cluster)
        else:
            _absorb(target, cluster)
    for weak in [item for item in result if _is_attribution_weak(item)]:
        candidates = [item for item in result if item is not weak and item.signal == weak.signal]
        if not candidates:
            continue
        target = max(candidates, key=lambda item: len(item.members))
        _absorb(target, weak)
        result.remove(weak)
    return result


def cluster_crashes(entries: list[dict], merge: bool = True) -> list[Cluster]:
    """聚类：``entries`` 元素含 ``file / signal / frames / fault_addr``；保序输出。

    ``fault_addr`` 仅参与 ``dedup_key``（取页号）；``frames`` 建议传入归一化后的
    前 12 帧（前 5 帧用于精确签名，余下留给合并规则）。
    """
    clusters: dict[str, Cluster] = {}
    for item in entries:
        key = dedup_key(item["signal"], item["frames"], item["fault_addr"])
        cluster = clusters.get(key)
        if cluster is None:
            cluster = Cluster(key=key, signal=item["signal"], frames=list(item["frames"]))
            clusters[key] = cluster
        cluster.members.append(item["file"])
    ordered = list(clusters.values())
    return merge_clusters(ordered) if merge else ordered
