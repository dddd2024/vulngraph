"""
Taint analysis adapter — delegates to the real taint engine.

This module acts as a thin adapter that bridges the ``BaseAnalyzer``
interface (used by the ``AnalyzerRegistry``) with the concrete taint
implementation in ``analyzers.python.engines.taint_engine.TaintEngine``.

Design
------
- For **Python** code units, the adapter writes content to a temporary
  file, loads taint rules from YAML, and delegates to ``TaintEngine``.
- For **non-Python** code units, it returns an empty list (no taint
  support yet).
- All heavy lifting stays in ``analyzers/python/engines/taint_engine.py``;
  this file only handles the ``CodeUnit`` → ``TaintEngine`` translation.

Note
----
The ``PythonAnalyzer`` (registered as ``"python"``) already runs the
taint engine internally.  This adapter exists so that a standalone
``"taint"`` analyzer is also available in the registry for callers who
want taint-only analysis.
"""

from __future__ import annotations

import logging
import os
import tempfile
from pathlib import Path
from typing import Any

from audit_core.models import CodeUnit, RawFinding
from analyzers.base import BaseAnalyzer

logger = logging.getLogger(__name__)


class TaintAnalyzer(BaseAnalyzer):
    """
    Adapter that delegates taint analysis to ``TaintEngine``.

    Registered in the ``AnalyzerRegistry`` under the name ``"taint"``.
    Only processes Python code units; other languages are silently skipped.
    """

    name = "taint"
    supported_languages = ["python"]

    def __init__(self) -> None:
        self._tmp_dir: str | None = None
        self._taint_rules: list[Any] | None = None
        self._rules_loaded: bool = False

    def analyze(self, code_units: list[CodeUnit]) -> list[RawFinding]:
        """
        Analyze code units using taint flow analysis.

        Only Python code units are processed.  For each unit, the content
        is written to a temporary file and passed to ``TaintEngine``.

        Args:
            code_units: List of code units to analyze

        Returns:
            List of ``RawFinding`` objects from taint analysis
        """
        findings: list[RawFinding] = []

        python_units = [u for u in code_units if (u.language or "").lower() == "python"]
        if not python_units:
            return findings

        self._ensure_rules_loaded()

        for unit in python_units:
            try:
                unit_findings = self._analyze_unit(unit)
                findings.extend(unit_findings)
            except Exception as exc:
                logger.warning("TaintAnalyzer failed for %s: %s", unit.path, exc)
                continue

        return findings

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _ensure_rules_loaded(self) -> None:
        """Load taint rules once from YAML configuration."""
        if self._rules_loaded:
            return

        try:
            from analyzers.python.core.rule_loader import load_yaml_rules
            from analyzers.python.core.models import Rule
        except ImportError as exc:
            logger.warning("TaintAnalyzer: cannot load rules: %s", exc)
            self._rules_loaded = True
            return

        all_rules: list[Any] = load_yaml_rules()
        self._taint_rules = [r for r in all_rules if getattr(r, 'engine', None) == "taint"]
        self._rules_loaded = True

    def _analyze_unit(self, unit: CodeUnit) -> list[RawFinding]:
        """Run TaintEngine on a single code unit."""
        from analyzers.python.engines.taint_engine import TaintEngine

        if not self._taint_rules:
            return []

        tmp_path = self._write_temp_file(unit)
        if tmp_path is None:
            return []

        engine = TaintEngine()
        taint_findings = engine.scan_file(tmp_path, self._taint_rules)

        return self._convert_findings(taint_findings, unit)

    def _write_temp_file(self, unit: CodeUnit) -> str | None:
        """Write code unit content to a temp .py file."""
        try:
            if self._tmp_dir is None:
                self._tmp_dir = tempfile.mkdtemp(prefix="vulnpatch_taint_")

            safe_name = unit.path.replace(os.sep, "_").replace("/", "_")
            for ch in ('<', '>', ':', '"', '|', '?', '*'):
                safe_name = safe_name.replace(ch, '_')
            if not safe_name or safe_name.startswith('_'):
                safe_name = f"snippet_{id(unit)}"
            if not safe_name.endswith(".py"):
                safe_name = safe_name + ".py"

            tmp_path = os.path.join(self._tmp_dir, safe_name)
            Path(tmp_path).write_text(unit.content, encoding="utf-8")
            return tmp_path
        except Exception as exc:
            logger.warning("TaintAnalyzer: failed to write temp file: %s", exc)
            return None

    @staticmethod
    def _convert_findings(taint_findings: list[Any], unit: CodeUnit) -> list[RawFinding]:
        """Convert TaintFinding objects to RawFinding objects."""
        results: list[RawFinding] = []

        for f in taint_findings:
            old = f.to_dict()
            vuln_type = old.get("type", "Unknown")
            line = old.get("line", 0)
            if not line:
                continue

            rule_id = old.get("rule_id") or f"TAINT_{vuln_type.replace(' ', '_').upper()}"

            severity = old.get("severity", "ERROR")
            severity_map = {
                "CRITICAL": "ERROR", "ERROR": "ERROR", "HIGH": "ERROR",
                "WARNING": "WARN", "WARN": "WARN", "MEDIUM": "WARN",
                "LOW": "INFO", "INFO": "INFO",
            }
            severity = severity_map.get(severity.upper(), "WARN")

            confidence = old.get("confidence", "medium")
            if confidence not in ("high", "medium", "low"):
                confidence = "medium"

            message = old.get("message") or f"Taint finding: {vuln_type}"

            evidence: dict[str, Any] = {}
            old_metadata = old.get("metadata")
            if old_metadata and isinstance(old_metadata, dict):
                for key in (
                    "taint_trace", "source", "sink",
                    "source_line", "sink_line",
                    "sanitized", "sanitizer",
                ):
                    if key in old_metadata:
                        evidence[key] = old_metadata[key]

            metadata: dict[str, Any] = {}
            if old_metadata and isinstance(old_metadata, dict):
                for k, v in old_metadata.items():
                    if k not in evidence:
                        metadata[k] = v

            results.append(RawFinding(
                rule_id=rule_id,
                type=vuln_type,
                cwe=old.get("cwe"),
                severity=severity,
                confidence=confidence,
                file_path=unit.path,
                start_line=line,
                message=message,
                engine="taint",
                evidence=evidence,
                metadata=metadata,
            ))

        return results

    def cleanup(self) -> None:
        """Remove temporary directory."""
        if self._tmp_dir is not None:
            try:
                import shutil
                shutil.rmtree(self._tmp_dir, ignore_errors=True)
            except Exception:
                pass
            self._tmp_dir = None

    def __del__(self) -> None:
        self.cleanup()
