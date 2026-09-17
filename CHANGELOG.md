# Changelog

本项目遵循 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/) 与 [语义化版本](https://semver.org/lang/zh-CN/)。

## [Unreleased]

### Added
- 仓库骨架：src 布局 / pyproject（hatchling + uv）/ CI（ubuntu × Python 3.11/3.12）
- `vulnforge doctor`：9 项环境自检（Python / 平台与 WSL / git / AFL++ / afl-clang-fast / gdb / tree-sitter（C+Python）/ 磁盘 / 工作目录）+ 一键修复命令 + `--json`
- **静态扫描引擎**（`vulnforge static scan`）：tree-sitter（C / Python）+ YAML 规则库（13 条内置：无界字符串 / 格式化串 / 命令注入 / 反序列化 / 弱随机等）；输出「位置 + 所在函数 + 规则 + 证据 + 建议」；`--json` 与 JSON / Markdown 导出

### Planned
- v0.1.0：静态扫描（C/Python）· 靶场 6 样本 · AFL++ 编排 · 崩溃去重与最小化 · CNVD 报告 · `vulnforge demo`
