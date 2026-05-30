"""
In-memory audit state.

Stores the most recent AuditResult so that sub-resource routes
(findings, evidence, agents, report) can read from it without
re-scanning.  No database is used.
"""

from __future__ import annotations

import threading

from audit_core.models import AuditResult, AuditSummary


class AuditState:
    """Thread-safe in-memory store for the latest audit result."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._result: AuditResult | None = None

    @property
    def has_result(self) -> bool:
        with self._lock:
            return self._result is not None

    def set(self, result: AuditResult) -> None:
        with self._lock:
            self._result = result

    def get(self) -> AuditResult:
        with self._lock:
            if self._result is None:
                return AuditResult(summary=AuditSummary())
            return self._result

    def clear(self) -> None:
        with self._lock:
            self._result = None


# Module-level singleton
audit_state = AuditState()
