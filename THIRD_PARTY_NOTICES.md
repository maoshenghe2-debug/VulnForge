# 第三方组件与许可说明

本项目以 **Apache-2.0** 发布（见 `LICENSE`）。运行时依赖与外部工具链如下：

| 组件 | 许可 | 使用方式 |
|---|---|---|
| Typer / Rich | MIT | Python CLI 与终端渲染 |
| PyYAML | MIT | 规则 / 配置解析 |
| Jinja2 | BSD-3-Clause | 报告模板 |
| tree-sitter / tree-sitter-language-pack | MIT | 源码解析（C / Python 等） |
| AFL++ | Apache-2.0 | **子进程调用**（官方工具链，不修改、不捆绑二进制） |
| afl-cmin / afl-tmin | Apache-2.0 | 官方脚本，直接调用 |
| gdb | GPL-3.0 | **仅子进程调用**（系统工具，非链接、非捆绑） |
| casr（可选对照） | Apache-2.0 | 子进程调用 |
| libFuzzer（v1.1 规划） | Apache-2.0 with LLVM exceptions | 规划中 |

**合规红线**：本项目不链接、不捆绑任何 GPL/LGPL/AGPL 组件；AFL++ 与 gdb
均以子进程方式调用系统工具，本项目代码中不引入其源代码。
