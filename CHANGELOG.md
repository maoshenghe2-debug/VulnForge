# Changelog

本项目遵循 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/) 与 [语义化版本](https://semver.org/lang/zh-CN/)。

## [Unreleased]

### Added
- 仓库骨架：src 布局 / pyproject（hatchling + uv）/ CI（ubuntu × Python 3.11/3.12）
- `vulnforge doctor`：9 项环境自检（Python / 平台与 WSL / git / AFL++ / afl-clang-fast / gdb / tree-sitter（C+Python）/ 磁盘 / 工作目录）+ 一键修复命令 + `--json`
- **静态扫描引擎**（`vulnforge static scan`）：tree-sitter（C / Python）+ YAML 规则库（13 条内置：无界字符串 / 格式化串 / 命令注入 / 反序列化 / 弱随机等）；输出「位置 + 所在函数 + 规则 + 证据 + 建议」；`--json` 与 JSON / Markdown 导出
- **fuzz 编排**（`vulnforge fuzz run / status / stop`）：afl-clang-fast 插桩构建（通用 harness 模板）+ 种子语料管理 + 多核（`-M` / `-S`）运行；`state.json`（≤5s 原子写）与 `build.json` 契约、`STOP` 优雅停止、`--resume` 断点续跑（`-i-`）；崩溃自动收集
- 首个靶场样本：栈溢出（`range/samples/stack_overflow.c`，教学用）
- 端到端实测：45s × 4 核 → 20,522 次执行 / 455.7 exec/s / 4 个崩溃（sig:11，已复现）
- **崩溃分类**（`vulnforge triage run`）：gdb 批处理提取信号 / 故障地址 / 归一化栈帧（地址剥离，未解析帧归一化常量）；`dedup_key = sha256(signal | top5 帧 | addr>>12)` 去重；afl-tmin 最小化；repro.sh（退出码 0=复现 / 1=未复现）
- 分类实测：3 个崩溃 → **1 个唯一缺陷**（`vuln_entry:14`，输入 66 → 41 字节，repro 退出码 0 已验证）
- 跨平台修复：AFL 崩溃文件名含 `:`，在 Windows/DrvFs 上暴露为私有区字符 U+F03A——收集阶段统一归一化为 `_`，收集与解析双平台一致

### Planned
- v0.1.0 剩余：靶场 6 样本 · 崩溃去重与最小化 · CNVD 报告 · `vulnforge demo`
