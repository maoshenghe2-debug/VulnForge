"""VulnForge 错误码与退出码（统一契约）。

退出码：0 成功 · 1 可用但有缺失（doctor）· 2 用法错误 · 3 环境不满足 · 4 运行期失败。
错误码：``VF-E<NNN>``（现象 → 原因 → 建议动作）。
"""

from __future__ import annotations

EXIT_OK = 0
EXIT_CHECK_WARN = 1
EXIT_USAGE = 2
EXIT_ENV = 3
EXIT_RUNTIME = 4


class VFError(Exception):
    """带错误码的业务异常（VF-E<NNN>），message 遵循「现象 → 原因 → 建议动作」。"""

    def __init__(self, code: str, message: str, fix: str = "") -> None:
        super().__init__(f"[{code}] {message}")
        self.code = code
        self.message = message
        self.fix = fix

    def __str__(self) -> str:  # pragma: no cover - 展示用途
        base = f"[{self.code}] {self.message}"
        return f"{base}；建议：{self.fix}" if self.fix else base
