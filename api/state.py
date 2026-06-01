"""
In-memory audit state with session management.

Stores scan_id -> AuditResult mappings so that multiple concurrent scans
do not overwrite each other.  Also maintains a "latest" pointer for
backward-compatible routes that don't specify a scan_id.

No database is used; state is held in memory only.
"""

from __future__ import annotations

import threading
import uuid
from typing import Optional

from audit_core.models import AuditResult, AuditSummary


class AuditState:
    """Thread-safe in-memory store for audit results with session management."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._sessions: dict[str, AuditResult] = {}
        self._latest_scan_id: str | None = None

    @property
    def has_result(self) -> bool:
        """Check if any scan result exists (latest)."""
        with self._lock:
            return self._latest_scan_id is not None

    def create_session(self, result: AuditResult) -> str:
        """
        Create a new session for the given AuditResult.

        Args:
            result: The audit result to store.

        Returns:
            The generated scan_id (UUID, first 12 chars).
        """
        scan_id = uuid.uuid4().hex[:12]
        with self._lock:
            self._sessions[scan_id] = result
            self._latest_scan_id = scan_id
        return scan_id

    def set_latest(self, result: AuditResult, scan_id: str) -> None:
        """
        Set the latest result and associate it with a scan_id.

        This is used internally by create_session; exposed for testing.

        Args:
            result: The audit result.
            scan_id: The scan session ID.
        """
        with self._lock:
            self._sessions[scan_id] = result
            self._latest_scan_id = scan_id

    def get_latest(self) -> AuditResult:
        """
        Get the most recent audit result.

        Returns:
            The latest AuditResult, or an empty result if none exists.
        """
        with self._lock:
            if self._latest_scan_id is None:
                return AuditResult(summary=AuditSummary())
            return self._sessions.get(self._latest_scan_id, AuditResult(summary=AuditSummary()))

    def get_by_id(self, scan_id: str) -> Optional[AuditResult]:
        """
        Get an audit result by scan_id.

        Args:
            scan_id: The scan session ID.

        Returns:
            The AuditResult if found, otherwise None.
        """
        with self._lock:
            return self._sessions.get(scan_id)

    def has_scan(self, scan_id: str) -> bool:
        """
        Check if a scan_id exists.

        Args:
            scan_id: The scan session ID.

        Returns:
            True if the scan_id exists.
        """
        with self._lock:
            return scan_id in self._sessions

    def clear(self) -> None:
        """Clear all stored results and sessions."""
        with self._lock:
            self._sessions.clear()
            self._latest_scan_id = None

    def get_scan_ids(self) -> list[str]:
        """
        Get all stored scan_ids.

        Returns:
            List of scan_id strings.
        """
        with self._lock:
            return list(self._sessions.keys())


# Module-level singleton
audit_state = AuditState()
