# VulnForge · 智能漏洞挖掘工作台

> 静态找点 → 模糊测试 → 崩溃分析 → 报告闭环：一条命令走通从源码到可提交漏洞报告的完整链路。

[![CI](https://github.com/maoshenghe2-debug/VulnForge/actions/workflows/ci.yml/badge.svg)](https://github.com/maoshenghe2-debug/VulnForge/actions/workflows/ci.yml)
![license](https://img.shields.io/badge/license-Apache--2.0-blue)
![python](https://img.shields.io/badge/python-3.11%20%7C%203.12-blue)

## 定位

VulnForge 面向**授权安全测试**场景（开源软件审计、自有系统测试、CNVD/CVE 漏洞报送），提供四段式闭环：

1. **静态分析**：tree-sitter 多语言解析 + YAML 可扩展的 source→sink 规则（C / Python 起步），输出候选点与调用链，指导 fuzz 目标选择
2. **模糊测试编排**：AFL++ 单引擎（WSL2 / Linux）+ harness 模板 + 语料管理 + 状态契约（断点续跑）
3. **崩溃分析**：ASAN / SIGSEGV 解析 · 栈哈希去重 · 最小化 PoC（`afl-tmin` + delta）· 复现验证
4. **报告闭环**：CNVD 风格报告（schema 校验）+ 崩溃日志 / PoC / 复现脚本证据链打包

## 快速上手

```bash
# 本机无 pip，统一 uv；Python 3.11
uv venv --python 3.11
uv pip install -e ".[all]"

vulnforge doctor      # 环境自检（≥8 项；Windows 下经 WSL2 探测并给出修复命令）
```

## 环境约定

| 项 | 约定 |
|---|---|
| 静态分析 / 报告 / CLI | 任意平台（Windows 原生可跑） |
| 模糊测试（AFL++） | **WSL2 Ubuntu 或 Linux**（`apt install afl++ clang llvm gdb`） |
| Docker | 不依赖（降级为可选） |

## 合规声明

- 仅用于**授权**测试：自有系统、开源软件安全审计、比赛靶场；
- 不包含武器化能力；漏洞披露遵循 CNVD / CVE 负责任披露流程；
- 仓库内全部靶场样本为**自写教学代码**，不含真实软件漏洞利用；
- 仓库不含任何真实凭证、内网信息与敏感数据。

## 设计说明（不重复造轮子）

Fuzzing 复用 **AFL++** 全家桶（子进程调用，`afl-cmin`/`afl-tmin` 直接用官方脚本）；静态解析复用 **tree-sitter**；崩溃分析引入 **casr**（Apache-2.0）为对照；自研保留：编排器 / harness 模板 / 去重与最小化策略层 / CNVD 报告 / 靶场。

## 许可

Apache-2.0（见 `LICENSE`；第三方依赖见 `THIRD_PARTY_NOTICES.md`）。
