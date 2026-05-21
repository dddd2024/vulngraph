"""RuleRegistry – 规则注册中心."""

from __future__ import annotations

from typing import Iterator

from detector.core.models import Rule


class RuleRegistry:
    """管理所有已注册的检测规则."""

    def __init__(self) -> None:
        self._rules: list[Rule] = []

    # ------------------------------------------------------------------
    # 注册
    # ------------------------------------------------------------------
    def register(self, rule: Rule) -> None:
        """注册单条规则."""
        self._rules.append(rule)

    def register_many(self, rules: list[Rule]) -> None:
        """批量注册规则."""
        self._rules.extend(rules)

    # ------------------------------------------------------------------
    # 查询
    # ------------------------------------------------------------------
    def get_rules(self, engine: str | None = None) -> list[Rule]:
        """获取规则列表，可按 engine 过滤."""
        if engine is None:
            return list(self._rules)
        return [r for r in self._rules if r.engine == engine]

    def __iter__(self) -> Iterator[Rule]:
        return iter(self._rules)

    def __len__(self) -> int:
        return len(self._rules)
