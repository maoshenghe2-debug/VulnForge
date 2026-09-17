"""vulnforge.report：CNVD 风格崩溃报告（schema 校验）。"""

from .generator import generate_report, to_markdown, validate_report

__all__ = ["generate_report", "to_markdown", "validate_report"]
