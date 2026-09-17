# Changelog

本项目遵循 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/) 与 [语义化版本](https://semver.org/lang/zh-CN/)。

## [0.1.0] - 2026-09-17

### Added
- 仓库骨架：src 布局 / pyproject（hatchling + uv）/ CI（ubuntu × Python 3.11/3.12）
- `vulnforge doctor`：9 项环境自检（Python / 平台与 WSL / git / AFL++ / afl-clang-fast / gdb / tree-sitter（C+Python）/ 磁盘 / 工作目录）+ 一键修复命令 + `--json`
- **静态扫描引擎**（`vulnforge static scan`）：tree-sitter（C / Python）+ YAML 规则库（13 条内置：无界字符串 / 格式化串 / 命令注入 / 反序列化等）；输出「位置 + 所在函数 + 规则 + 证据 + 建议」；`--json` 与 JSON / Markdown 导出
- **fuzz 编排**（`vulnforge fuzz run / status / stop`）：afl-clang-fast 插桩构建（通用 harness 模板）+ 种子语料管理 + 多核（`-M` / `-S`）运行；`state.json`（≤5s 原子写）与 `build.json` 契约、`STOP` 优雅停止、`--resume` 断点续跑（`-i-`）；崩溃自动收集
- 靶场样本 ×6（`range/samples/`，自写教学用）：栈溢出 / 堆越界写 / 双重释放 / 整数溢出 / 格式化字符串 / 命令注入；每样本配套种子语料（`range/seeds/`）
- 端到端实测：45s × 4 核 → 20,522 次执行 / 455.7 exec/s / 4 个崩溃（sig:11，已复现）
- **崩溃分类**（`vulnforge triage run`）：gdb 批处理提取信号 / 故障地址 / 归一化栈帧（地址剥离，未解析帧归一化常量）；`dedup_key = sha256(signal | top5 帧 | addr>>12)` 去重；afl-tmin 最小化；repro.sh（退出码 0=复现 / 1=未复现）
- 分类实测：3 个崩溃 → **1 个唯一缺陷**（`vuln_entry:14`，输入 66 → 41 字节，repro 退出码 0 已验证）
- **聚类合并**（R1 归因弱簇 / R2 同源帧；仅任务内生效）+ golden 标注集 pairwise **F1 = 1.000**（6 靶场 / 11 真实崩溃，契约 ≥0.95）
- **CNVD 风格报告**（`vulnforge report`）：JSON schema 校验 + Markdown 渲染；证据链（输入 / 崩溃文件 SHA-256、复现脚本、归一化栈帧、静态修复建议）+ 候选缺陷口径声明
- **`vulnforge demo`** 单链路：静态 → fuzz → 分类 → 报告，实测 22.5s（≤10 分钟契约）
- 演示素材：GIF + 5 张终端截图（全部基于真实 CLI 输出渲染）

### Fixed
- 跨平台：AFL 崩溃文件名含 `:`，在 Windows/DrvFs 上暴露为私有区字符 U+F03A——收集阶段统一归一化为 `_`，收集与解析双平台一致
- 收集链路：含通配符 / 变量的复杂 shell 逻辑移入 `run.sh` 脚本文件执行（经 wsl.exe 传递的字符串会清空未匹配 Windows 文件的 glob，导致静默零收集）
- 子进程输出解码：剥离 ANSI 转义序列（`afl-fuzz --version` 彩色输出污染自检详情）
- 样本设计（实测教训沉淀于样本注释）：clang -O1 死存储消除会删除「写后即 free」的 memcpy（增读回 sink）；种子必须保留至少一个不崩溃（AFL++ 启动硬约束）；小越界量被 glibc tcache 吞掉不报错（改固定大越界量 / 32 位回绕）
