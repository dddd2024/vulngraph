"""
Legacy analyzer adapter — Python-only transition adapter.

This module provides a **transitional bridge** between the new audit pipeline
and the old Python-only ``DetectorRunner`` (AST + Plugin + Regex + Taint).

It wraps the old ``DetectorRunner`` and converts its ``list[dict]`` findings
into ``list[RawFinding]`` objects that the new audit pipeline can consume.

This adapter is **Python-only**.  It exists solely to keep the legacy Python
detector functional while the new analyzers are being built out.  Non-Python
languages are handled by dedicated, language-native analyzers in the
``analyzers/`` package and are **not** routed through this adapter.
"""

import logging
import os
import tempfile
from pathlib import Path
from typing import Any

from audit_core.models import CodeUnit, RawFinding
from analyzers.base import BaseAnalyzer

logger = logging.getLogger(__name__)


class LegacyAnalyzerAdapter(BaseAnalyzer):
    """
    Python-only transition adapter for the legacy DetectorRunner.

    This adapter wraps the old ``DetectorRunner`` and converts its
    ``list[dict]`` findings into ``list[RawFinding]`` objects that
    the new audit pipeline can consume.

    It only handles Python code units — for each one it writes content
    to a temporary file and runs ``DetectorRunner.scan_file()``, which
    executes:
      - AST YAML rule engine
      - Python Plugin engine
      - Regex YAML rule engine
      - Taint analysis engine

    Non-Python languages are **not** supported by this adapter; they
    are served by dedicated, language-native analyzers elsewhere in
    the ``analyzers/`` package.
    """

    name = "legacy"
    supported_languages = ["python"]

    def __init__(self) -> None:
        self._runner = None
        self._tmp_dir: tempfile.TemporaryDirectory | None = None

    def _get_runner(self):
        """Lazy-load the DetectorRunner."""
        if self._runner is None:
            from detector.core.runner import DetectorRunner
            self._runner = DetectorRunner()
        return self._runner

    def _ensure_tmp_dir(self) -> Path:
        """Ensure a temporary directory exists for writing code units."""
        if self._tmp_dir is None:
            self._tmp_dir = tempfile.TemporaryDirectory(prefix="vulnpatch_legacy_")
        return Path(self._tmp_dir.name)

    def analyze(self, code_units: list[CodeUnit]) -> list[RawFinding]:
        """
        Analyze Python code units using legacy detection logic.

        For each Python code unit:
        1. Write content to a temporary file (preserving original extension)
        2. Run DetectorRunner.scan_file() on the temp file
        3. Convert each finding dict to a RawFinding

        Non-Python code units are silently skipped.

        Args:
            code_units: List of code units to analyze

        Returns:
            List of RawFinding objects from legacy detectors
        """
        findings: list[RawFinding] = []
        runner = self._get_runner()

        for unit in code_units:
            if unit.language != "python":
                continue

            try:
                unit_findings = self._analyze_python_unit(runner, unit)
                findings.extend(unit_findings)
            except Exception as exc:
                logger.warning(
                    "Legacy analysis failed for %s: %s", unit.path, exc
                )
                continue

        return findings

    def _analyze_python_unit(
        self, runner, unit: CodeUnit
    ) -> list[RawFinding]:
        """
        Analyze a single Python code unit using DetectorRunner.

        Writes the code unit content to a temp file, runs the detector,
        and converts findings to RawFinding objects.
        """
        tmp_dir = self._ensure_tmp_dir()

        # Determine temp file path: preserve .py extension for AST parsing
        # Sanitize path to be a valid filename (remove <, >, :, *, ?, etc.)
        safe_name = unit.path.replace(os.sep, "_").replace("/", "_")
        # Remove characters invalid on Windows
        for ch in ('<', '>', ':', '"', '|', '?', '*'):
            safe_name = safe_name.replace(ch, '_')
        if not safe_name or safe_name.startswith('_'):
            safe_name = f"snippet_{id(unit)}"
        if not safe_name.endswith(".py"):
            safe_name = safe_name + ".py"
        tmp_file = tmp_dir / safe_name

        # Write code content to temp file
        tmp_file.write_text(unit.content, encoding="utf-8")

        # Run DetectorRunner on the temp file
        old_findings: list[dict[str, Any]] = runner.scan_file(str(tmp_file))

        # Convert each old finding dict to RawFinding
        results: list[RawFinding] = []
        for old_f in old_findings:
            try:
                raw_finding = self._convert_finding(old_f, unit)
                if raw_finding is not None:
                    results.append(raw_finding)
            except Exception as exc:
                logger.warning(
                    "Failed to convert finding for %s: %s", unit.path, exc
                )
                continue

        return results

    def _convert_finding(
        self, old: dict[str, Any], unit: CodeUnit
    ) -> RawFinding | None:
        """
        Convert an old finding dict to a RawFinding.

        Old finding dict format (varies by engine):
          - type: str (vulnerability type)
          - file: str (file path)
          - line: int (line number)
          - symbol: str (related symbol, optional)
          - severity: str ("ERROR", "WARNING", etc.)
          - engine: str ("ast", "regex", "taint", "tree-sitter")
          - detector: str (detector function name, optional)
          - confidence: str (optional)
          - rule_id: str (optional, from YAML rules)
          - cwe: str (optional)
          - message: str (optional)
          - detail: str (optional)
          - metadata: dict (optional, especially for taint findings)
          - language: str (optional)

        RawFinding fields:
          - rule_id: generated from type + engine if not present
          - type: vulnerability type
          - cwe: CWE identifier (if available)
          - severity: mapped to standard levels
          - confidence: from old finding or default
          - file_path: from CodeUnit.path
          - start_line: from old finding line
          - message: description of the finding
          - engine: "legacy"
          - evidence: preserved old finding metadata
        """
        vuln_type = old.get("type", "Unknown")
        line = old.get("line", 0)
        if not line:
            return None

        # Generate rule_id if not present
        rule_id = old.get("rule_id")
        if not rule_id:
            detector_name = old.get("detector", "")
            engine = old.get("engine", "unknown")
            safe_type = vuln_type.replace(" ", "_").replace("(", "").replace(")", "")
            if detector_name:
                rule_id = f"LEGACY_{detector_name.upper()}"
            else:
                rule_id = f"LEGACY_{safe_type.upper()}_{engine.upper()}"

        # Map severity to standard levels
        severity = old.get("severity", "ERROR")
        severity = self._map_severity(severity)

        # Map confidence
        confidence = old.get("confidence", "medium")
        if confidence not in ("high", "medium", "low"):
            confidence = "medium"

        # Build message
        message = old.get("message") or old.get("detail") or f"Legacy finding: {vuln_type}"

        # Build evidence dict - preserve all old finding info
        evidence: dict[str, Any] = {}
        if old.get("symbol"):
            evidence["symbol"] = old["symbol"]
        if old.get("detail"):
            evidence["detail"] = old["detail"]
        if old.get("detector"):
            evidence["detector"] = old["detector"]
        if old.get("engine"):
            evidence["legacy_engine"] = old["engine"]
        if old.get("language"):
            evidence["language"] = old["language"]

        # Preserve taint-specific metadata
        old_metadata = old.get("metadata")
        if old_metadata and isinstance(old_metadata, dict):
            # Copy taint trace and other metadata into evidence
            for key in ("taint_trace", "source", "sink", "source_line",
                        "sink_line", "sanitized", "sanitizer"):
                if key in old_metadata:
                    evidence[key] = old_metadata[key]

        # Build metadata dict for additional info
        metadata: dict[str, Any] = {}
        if old_metadata and isinstance(old_metadata, dict):
            # Keep everything else in metadata
            for k, v in old_metadata.items():
                if k not in evidence:
                    metadata[k] = v

        # CWE from old finding
        cwe = old.get("cwe")

        return RawFinding(
            rule_id=rule_id,
            type=vuln_type,
            cwe=cwe,
            severity=severity,
            confidence=confidence,
            file_path=unit.path,
            start_line=line,
            message=message,
            engine=self.name,
            evidence=evidence,
            metadata=metadata,
        )

    @staticmethod
    def _map_severity(severity: str) -> str:
        """Map old severity strings to standard levels."""
        mapping = {
            "CRITICAL": "ERROR",
            "ERROR": "ERROR",
            "HIGH": "ERROR",
            "WARNING": "WARN",
            "WARN": "WARN",
            "MEDIUM": "WARN",
            "LOW": "INFO",
            "INFO": "INFO",
        }
        return mapping.get(severity.upper(), "WARN")

    def cleanup(self) -> None:
        """Clean up temporary files."""
        if self._tmp_dir is not None:
            try:
                self._tmp_dir.cleanup()
            except Exception:
                pass
            self._tmp_dir = None

    def __del__(self) -> None:
        self.cleanup()
