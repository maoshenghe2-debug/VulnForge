"""VulnForge · 智能漏洞挖掘工作台（静态分析 → 模糊测试 → 崩溃分析 → 报告闭环）。

模块规划：
- ``vulnforge.doctor``   环境自检（WSL2 / AFL++ / tree-sitter 探测）
- ``vulnforge.static``   静态分析（tree-sitter + YAML 规则）
- ``vulnforge.fuzz``     模糊测试编排（AFL++ 单引擎）
- ``vulnforge.triage``   崩溃解析 / 去重 / 最小化
- ``vulnforge.report``   报告生成（CNVD / CVE 风格）
- ``vulnforge.range``    自建靶场与基准
"""

__version__ = "0.1.0"
__author__ = "Maosheng He (maoshenghe2-debug)"
