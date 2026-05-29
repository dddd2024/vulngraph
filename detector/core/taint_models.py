"""污点分析数据模型 – 定义污点传播追踪和检测结果的数据结构."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class TaintTraceStep:
    """污点传播路径中的单个步骤."""

    file: str = ""
    line: int = 0
    col: int = 0
    node_type: str = ""  # "source" | "propagation" | "sanitizer" | "sink"
    code_snippet: str = ""  # 该步骤的代码片段
    variable: str = ""  # 涉及的变量名
    description: str = ""  # 步骤描述

    def to_dict(self) -> dict[str, Any]:
        """转换为字典格式."""
        return {
            "file": self.file,
            "line": self.line,
            "col": self.col,
            "node_type": self.node_type,
            "code_snippet": self.code_snippet,
            "variable": self.variable,
            "description": self.description,
        }


@dataclass
class TaintFinding:
    """污点分析检测结果."""

    # 核心字段（兼容现有 Finding 格式）
    type: str = ""  # 漏洞类型，如 "SQL Injection"
    file: str = ""
    line: int = 0
    severity: str = "ERROR"
    engine: str = "taint"
    confidence: str = "medium"

    # 规则相关字段
    rule_id: str = ""
    cwe: str = ""
    message: str = ""

    # 污点分析特有字段
    source: str = ""  # 污点源（如 "request.args.get"）
    sink: str = ""  # 污点汇（如 "cursor.execute"）
    source_line: int = 0  # 污点源行号
    sink_line: int = 0  # 污点汇行号
    taint_trace: list[TaintTraceStep] = field(default_factory=list)  # 污点传播路径
    sanitized: bool = False  # 是否经过净化器
    sanitizer: str = ""  # 使用的净化器（如果有）

    # 元数据
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """转换为字典格式，兼容现有 finding 格式，并把 taint_trace 放入 metadata."""
        d: dict[str, Any] = {
            "type": self.type,
            "file": self.file,
            "line": self.line,
            "severity": self.severity,
            "engine": self.engine,
            "confidence": self.confidence,
        }

        # 规则相关字段
        if self.rule_id:
            d["rule_id"] = self.rule_id
        if self.cwe:
            d["cwe"] = self.cwe
        if self.message:
            d["message"] = self.message

        # 构建 metadata，包含污点分析特有信息
        metadata: dict[str, Any] = dict(self.metadata) if self.metadata else {}

        # 添加污点追踪信息
        if self.taint_trace:
            metadata["taint_trace"] = [step.to_dict() for step in self.taint_trace]

        # 添加污点源和汇信息
        metadata["source"] = self.source
        metadata["sink"] = self.sink
        metadata["source_line"] = self.source_line
        metadata["sink_line"] = self.sink_line

        # 添加净化器信息
        if self.sanitized:
            metadata["sanitized"] = self.sanitized
        if self.sanitizer:
            metadata["sanitizer"] = self.sanitizer

        if metadata:
            d["metadata"] = metadata

        return d


@dataclass
class TaintVariable:
    """污点变量状态，用于污点传播分析."""

    name: str = ""
    tainted: bool = False
    source: str = ""  # 污点来源
    source_line: int = 0
    sanitized: bool = False
    sanitizer: str = ""  # 使用的净化器
    trace_steps: list[TaintTraceStep] = field(default_factory=list)

    def copy(self) -> TaintVariable:
        """创建副本."""
        return TaintVariable(
            name=self.name,
            tainted=self.tainted,
            source=self.source,
            source_line=self.source_line,
            sanitized=self.sanitized,
            sanitizer=self.sanitizer,
            trace_steps=list(self.trace_steps),
        )


@dataclass
class TaintRuleConfig:
    """污点规则配置，从 YAML 规则加载."""

    # 污点源配置
    sources: list[dict[str, Any]] = field(default_factory=list)
    # 污点汇配置
    sinks: list[dict[str, Any]] = field(default_factory=list)
    # 净化器配置
    sanitizers: list[dict[str, Any]] = field(default_factory=list)

    # 规则元信息
    rule_id: str = ""
    rule_name: str = ""
    severity: str = "ERROR"
    cwe: str = ""
    confidence: str = "medium"
    message: str = ""
    language: str = "python"
    enabled: bool = True

    @classmethod
    def from_yaml(cls, raw: dict[str, Any]) -> TaintRuleConfig:
        """从 YAML 规则字典创建配置."""
        return cls(
            sources=raw.get("sources", []),
            sinks=raw.get("sinks", []),
            sanitizers=raw.get("sanitizers", []),
            rule_id=raw.get("id", ""),
            rule_name=raw.get("name", ""),
            severity=raw.get("severity", "ERROR"),
            cwe=raw.get("cwe", ""),
            confidence=raw.get("confidence", "medium"),
            message=raw.get("message", ""),
            language=raw.get("language", "python"),
            enabled=raw.get("enabled", True),
        )