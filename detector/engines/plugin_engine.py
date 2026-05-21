"""Plugin Engine – 执行 Python Plugin 复杂规则."""

from __future__ import annotations

from importlib import import_module
from typing import Any

# 已注册的 plugin 列表：(module_path, plugin_name)
PLUGINS: list[tuple[str, str]] = [
    ("detector.plugins.sql_injection", "run"),
    ("detector.plugins.path_traversal", "run"),
    ("detector.plugins.privilege_escalation", "run"),
    ("detector.plugins.multilang", "run"),  # 多语言检测（JS/TS/Java/C/C++）
    ("detector.plugins.ml_detection", "run"),  # ML 深度学习检测
]


class PluginEngine:
    """执行所有已注册的 Python Plugin."""

    def __init__(self, plugins: list[tuple[str, str]] | None = None) -> None:
        self._plugins = plugins or PLUGINS
        # 缓存已加载的 plugin 函数
        self._cache: dict[str, Any] = {}

    def _load_plugin(self, module_path: str, func_name: str) -> Any:
        key = f"{module_path}:{func_name}"
        if key not in self._cache:
            mod = import_module(module_path)
            self._cache[key] = getattr(mod, func_name)
        return self._cache[key]

    def scan_file(self, file_path: str) -> list[dict[str, Any]]:
        """对单个文件运行所有 plugin，返回合并的 finding 列表."""
        all_findings: list[dict[str, Any]] = []
        for module_path, func_name in self._plugins:
            try:
                plugin_fn = self._load_plugin(module_path, func_name)
                findings = plugin_fn(file_path)
                all_findings.extend(findings)
            except Exception:
                continue
        return all_findings
