"""DetectorRunner – 统一检测入口.

第一阶段：包装现有 detect_xxx 函数（scan_file_with_builtin_detectors）.
第六阶段新增：DetectorRunner 类，同时执行 AST YAML 规则 + Python plugins.
第七阶段新增：RegexRuleEngine 集成.
"""

from __future__ import annotations

from typing import Any

from detector.core.rule_loader import load_yaml_rules
from detector.engines.ast_rule_engine import AstRuleEngine
from detector.engines.plugin_engine import PluginEngine
from detector.engines.regex_rule_engine import RegexRuleEngine
from detector.vuln_detector import (
    detect_command_injection,
    detect_dangerous_code_execution,
    detect_debug_mode,
    detect_hardcoded_secret,
    detect_insecure_tls,
    detect_path_traversal,
    detect_privilege_escalation,
    detect_sql_injection,
    detect_unsafe_deserialization,
    detect_weak_crypto,
)

# ---------------------------------------------------------------------------
# 内置检测器注册表：name -> (callable, default_confidence)
# ---------------------------------------------------------------------------
_BUILTIN_DETECTORS: list[tuple[str, Any, str]] = [
    ("detect_sql_injection", detect_sql_injection, "high"),
    ("detect_path_traversal", detect_path_traversal, "medium"),
    ("detect_privilege_escalation", detect_privilege_escalation, "medium"),
    ("detect_dangerous_code_execution", detect_dangerous_code_execution, "high"),
    ("detect_command_injection", detect_command_injection, "high"),
    ("detect_unsafe_deserialization", detect_unsafe_deserialization, "high"),
    ("detect_hardcoded_secret", detect_hardcoded_secret, "medium"),
    ("detect_weak_crypto", detect_weak_crypto, "medium"),
    ("detect_debug_mode", detect_debug_mode, "medium"),
    ("detect_insecure_tls", detect_insecure_tls, "medium"),
]


def scan_file_with_builtin_detectors(file_path: str) -> list[dict[str, Any]]:
    """对单个文件运行全部内置 AST 检测器，返回增强后的 finding 列表.

    每个 finding 在原有字段基础上补充 ``engine``、``detector``、``confidence``.

    如果所有检测器都因异常失败，抛出第一个异常（通常是 SyntaxError），
    以便调用方可以记录到 skipped_details.
    """
    all_findings: list[dict[str, Any]] = []
    first_error: Exception | None = None
    for detector_name, detector_fn, default_confidence in _BUILTIN_DETECTORS:
        try:
            raw_findings = detector_fn(file_path)
        except Exception as exc:
            if first_error is None:
                first_error = exc
            continue
        for f in raw_findings:
            f.setdefault("engine", "ast")
            f["detector"] = detector_name
            f.setdefault("confidence", default_confidence)
            all_findings.append(f)
    if not all_findings and first_error is not None:
        raise first_error
    return all_findings


# ---------------------------------------------------------------------------
# DetectorRunner – 统一引擎调度器
# ---------------------------------------------------------------------------
class DetectorRunner:
    """统一检测入口：同时执行 AST YAML 规则 + Python Plugin + Regex 引擎.

    用法::

        runner = DetectorRunner()
        findings = runner.scan_file("path/to/file.py")
    """

    def __init__(
        self,
        ast_engine: AstRuleEngine | None = None,
        plugin_engine: PluginEngine | None = None,
        regex_engine: RegexRuleEngine | None = None,
        rules_dir: str | None = None,
    ) -> None:
        self._ast_engine = ast_engine or AstRuleEngine()
        self._plugin_engine = plugin_engine or PluginEngine()
        self._regex_engine = regex_engine or RegexRuleEngine()
        self._rules_dir = rules_dir
        # 延迟加载规则
        self._ast_rules: list[Any] | None = None
        self._regex_rules: list[Any] | None = None

    def _get_ast_rules(self) -> list[Any]:
        if self._ast_rules is None:
            self._ast_rules = [
                r for r in load_yaml_rules(self._rules_dir) if r.engine == "ast"
            ]
        return self._ast_rules

    def _get_regex_rules(self) -> list[Any]:
        if self._regex_rules is None:
            self._regex_rules = [
                r for r in load_yaml_rules(self._rules_dir) if r.engine == "regex"
            ]
        return self._regex_rules

    def scan_file(self, file_path: str) -> list[dict[str, Any]]:
        """对单个文件运行所有引擎，返回合并的 finding 列表（dict 格式）.

        如果所有引擎都因异常失败且没有产出任何 finding，
        抛出第一个异常（通常是 SyntaxError），
        以便调用方可以记录到 skipped_details.
        """
        import ast as _ast
        from pathlib import Path as _Path

        # 预检查：尝试解析文件，如果是 SyntaxError 直接抛出
        try:
            source = _Path(file_path).read_text(encoding="utf-8")
            _ast.parse(source)
        except SyntaxError:
            raise
        except Exception:
            pass

        all_findings: list[dict[str, Any]] = []
        first_error: Exception | None = None

        def _safe_run(fn) -> None:
            nonlocal first_error
            try:
                results = fn()
                all_findings.extend(results)
            except Exception as exc:
                if first_error is None:
                    first_error = exc

        # 1. AST YAML 规则引擎
        ast_rules = self._get_ast_rules()
        if ast_rules:
            _safe_run(lambda r=ast_rules: [f.to_dict() for f in self._ast_engine.scan_file(file_path, r)])

        # 2. Python Plugin 引擎
        _safe_run(lambda: self._plugin_engine.scan_file(file_path))

        # 3. Regex YAML 规则引擎
        regex_rules = self._get_regex_rules()
        if regex_rules:
            _safe_run(lambda r=regex_rules: [f.to_dict() for f in self._regex_engine.scan_file(file_path, r)])

        if not all_findings and first_error is not None:
            raise first_error

        return all_findings
