"""Rule / Finding 数据模型."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class Rule:
    """一条检测规则的定义."""

    id: str
    name: str
    type: str  # "ast" | "regex" | "plugin"
    severity: str  # "ERROR" | "WARNING" | "INFO"
    engine: str  # "ast" | "regex" | "plugin"
    language: str = "python"
    cwe: str = ""
    confidence: str = "medium"  # "high" | "medium" | "low"
    message: str = ""
    enabled: bool = True
    pattern: dict[str, Any] = field(default_factory=dict)


@dataclass
class Finding:
    """一条检测结果."""

    rule_id: str = ""
    type: str = ""
    file: str = ""
    line: int = 0
    symbol: str = ""
    severity: str = "ERROR"
    engine: str = "ast"
    confidence: str = "medium"
    cwe: str = ""
    message: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)

    # ------------------------------------------------------------------
    # 兼容性：to_dict() 输出必须包含现有 finding 的所有字段
    # ------------------------------------------------------------------
    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "type": self.type,
            "file": self.file,
            "line": self.line,
            "symbol": self.symbol,
            "severity": self.severity,
            "engine": self.engine,
        }
        # 新增字段（仅在有值时添加）
        if self.rule_id:
            d["rule_id"] = self.rule_id
        if self.cwe:
            d["cwe"] = self.cwe
        if self.confidence:
            d["confidence"] = self.confidence
        if self.message:
            d["message"] = self.message
        if self.metadata:
            d["metadata"] = self.metadata
        return d
