"""
In-memory audit state.

Stores the most recent AuditResult so that sub-resource routes
(findings, evidence, agents, report) can read from it without
re-scanning.  No database is used.
"""

from __future__ import annotations

from audit_core.models import AuditResult, AuditSummary


class AuditState:
    """Thread-safe in-memory store for the latest audit result."""

    def __init__(self) -> None:
        self._result: AuditResult | None = None

    @property
    def has_result(self) -> bool:
        return self._result is not None

    def set(self, result: AuditResult) -> None:
        self._result = result

    def get(self) -> AuditResult:
        if self._result is None:
            return AuditResult(summary=AuditSummary())
        return self._result

    def clear(self) -> None:
        self._result = None


# Module-level singleton
audit_state = AuditState()
