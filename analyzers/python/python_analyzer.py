"""
PythonAnalyzer — adapter that wraps detector engines into the BaseAnalyzer interface.

Design decisions
----------------
* Does **not** copy any detection logic — directly imports and delegates to
  ``detector.engines.ast_rule_engine.AstRuleEngine``,
  ``detector.engines.regex_rule_engine.RegexRuleEngine``, and
  ``detector.engines.taint_engine.TaintEngine``.
* All imports of detector modules are **lazy** (inside methods) so that the
  package can be imported even when the detector sub-tree is absent.
* Rules are loaded once via ``detector.core.rule_loader.load_yaml_rules()`` and
  grouped by engine type before being passed to each engine.
* Each engine call is wrapped in ``_safe_run()`` so that a failure in one
  engine does not prevent the others from running.
"""

from __future__ import annotations

import logging
import os
import tempfile
from pathlib import Path
from typing import Any

from analyzers.base import BaseAnalyzer
from audit_core.models import CodeUnit, RawFinding

logger = logging.getLogger(__name__)


class PythonAnalyzer(BaseAnalyzer):
    """
    Unified Python analyzer backed by the detector's AST, Regex, and Taint
    engines.

    Produces ``RawFinding`` objects whose ``engine`` field is ``"python"``
    (as opposed to ``"legacy"`` used by ``LegacyAnalyzerAdapter``).
    """

    name = "python"
    supported_languages = ["python"]

    # ------------------------------------------------------------------
    # Construction / lifecycle
    # ------------------------------------------------------------------

    def __init__(self) -> None:
        self._tmp_dir: str | None = None
        # Cached rule lists — populated on first use
        self._ast_rules: list | None = None
        self._regex_rules: list | None = None
        self._taint_rules: list | None = None
        self._rules_loaded: bool = False

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def analyze(self, code_units: list[CodeUnit]) -> list[RawFinding]:
        """
        Analyze *code_units* and return a list of ``RawFinding`` objects.

        Only Python code units are processed; all others are silently skipped.
        """
        findings: list[RawFinding] = []

        python_units = [u for u in code_units if u.language == "python"]
        if not python_units:
            return findings

        # Lazily load and group rules (once per analyzer instance)
        self._ensure_rules_loaded()

        for unit in python_units:
            try:
                unit_findings = self._analyze_unit(unit)
                findings.extend(unit_findings)
            except Exception as exc:
                logger.warning("PythonAnalyzer failed for %s: %s", unit.path, exc)
                continue

        return findings

    def cleanup(self) -> None:
        """Remove the temporary directory used for writing code-unit files."""
        if self._tmp_dir is not None:
            try:
                import shutil
                shutil.rmtree(self._tmp_dir, ignore_errors=True)
            except Exception:
                pass
            self._tmp_dir = None

    def __del__(self) -> None:
        self.cleanup()

    # ------------------------------------------------------------------
    # Internal: rule loading
    # ------------------------------------------------------------------

    def _ensure_rules_loaded(self) -> None:
        """Load YAML rules once and split them by engine type."""
        if self._rules_loaded:
            return

        try:
            from detector.core.rule_loader import load_yaml_rules
            from detector.core.models import Rule
        except ImportError as exc:
            logger.warning("Cannot load detector rules: %s", exc)
            self._rules_loaded = True
            return

        all_rules: list[Rule] = load_yaml_rules()

        self._ast_rules = [r for r in all_rules if r.engine == "ast"]
        self._regex_rules = [r for r in all_rules if r.engine == "regex"]
        self._taint_rules = [r for r in all_rules if r.engine == "taint"]
        self._rules_loaded = True

    # ------------------------------------------------------------------
    # Internal: per-unit analysis
    # ------------------------------------------------------------------

    def _analyze_unit(self, unit: CodeUnit) -> list[RawFinding]:
        """Run all three engines on a single code unit."""
        tmp_path = self._write_temp_file(unit)
        if tmp_path is None:
            return []

        findings: list[RawFinding] = []

        # 1. AST rule engine
        ast_findings = self._safe_run(self._run_ast_engine, tmp_path, unit)
        findings.extend(ast_findings)

        # 2. Regex rule engine
        regex_findings = self._safe_run(self._run_regex_engine, tmp_path, unit)
        findings.extend(regex_findings)

        # 3. Taint engine
        taint_findings = self._safe_run(self._run_taint_engine, tmp_path, unit)
        findings.extend(taint_findings)

        return findings

    # ------------------------------------------------------------------
    # Internal: temp-file helpers
    # ------------------------------------------------------------------

    def _ensure_tmp_dir(self) -> str:
        """Create (or return) a persistent temporary directory."""
        if self._tmp_dir is None:
            self._tmp_dir = tempfile.mkdtemp(prefix="vulnpatch_python_")
        return self._tmp_dir

    def _write_temp_file(self, unit: CodeUnit) -> str | None:
        """
        Write the code unit content to a temporary ``.py`` file and return
        its absolute path.  Returns ``None`` on failure.
        """
        try:
            tmp_dir = self._ensure_tmp_dir()

            # Build a safe filename preserving the .py extension
            safe_name = unit.path.replace(os.sep, "_").replace("/", "_")
            for ch in ('<', '>', ':', '"', '|', '?', '*'):
                safe_name = safe_name.replace(ch, '_')
            if not safe_name or safe_name.startswith('_'):
                safe_name = f"snippet_{id(unit)}"
            if not safe_name.endswith(".py"):
                safe_name = safe_name + ".py"

            tmp_path = os.path.join(tmp_dir, safe_name)
            Path(tmp_path).write_text(unit.content, encoding="utf-8")
            return tmp_path
        except Exception as exc:
            logger.warning("Failed to write temp file for %s: %s", unit.path, exc)
            return None

    # ------------------------------------------------------------------
    # Internal: engine runners
    # ------------------------------------------------------------------

    def _run_ast_engine(self, tmp_path: str, unit: CodeUnit) -> list[RawFinding]:
        """Run the AST rule engine and convert findings."""
        from detector.engines.ast_rule_engine import AstRuleEngine

        if not self._ast_rules:
            return []

        engine = AstRuleEngine()
        findings = engine.scan_file(tmp_path, self._ast_rules)

        results: list[RawFinding] = []
        for f in findings:
            old = f.to_dict()
            converted = self._convert_finding(old, unit)
            if converted is not None:
                results.append(converted)
        return results

    def _run_regex_engine(self, tmp_path: str, unit: CodeUnit) -> list[RawFinding]:
        """Run the Regex rule engine and convert findings."""
        from detector.engines.regex_rule_engine import RegexRuleEngine

        if not self._regex_rules:
            return []

        engine = RegexRuleEngine()
        findings = engine.scan_file(tmp_path, self._regex_rules)

        results: list[RawFinding] = []
        for f in findings:
            old = f.to_dict()
            converted = self._convert_finding(old, unit)
            if converted is not None:
                results.append(converted)
        return results

    def _run_taint_engine(self, tmp_path: str, unit: CodeUnit) -> list[RawFinding]:
        """Run the Taint engine and convert findings."""
        from detector.engines.taint_engine import TaintEngine

        if not self._taint_rules:
            return []

        engine = TaintEngine()
        findings = engine.scan_file(tmp_path, self._taint_rules)

        results: list[RawFinding] = []
        for f in findings:
            old = f.to_dict()
            converted = self._convert_finding(old, unit)
            if converted is not None:
                results.append(converted)
        return results

    # ------------------------------------------------------------------
    # Internal: safe execution wrapper
    # ------------------------------------------------------------------

    @staticmethod
    def _safe_run(func, *args: Any) -> list[RawFinding]:
        """
        Execute *func* with *args* and return its result.

        If *func* raises any exception, log a warning and return an empty
        list so that other engines can still proceed.
        """
        try:
            return func(*args)
        except Exception as exc:
            logger.warning("Engine %s failed: %s", getattr(func, '__name__', repr(func)), exc)
            return []

    # ------------------------------------------------------------------
    # Internal: finding conversion
    # ------------------------------------------------------------------

    def _convert_finding(
        self, old: dict[str, Any], unit: CodeUnit
    ) -> RawFinding | None:
        """
        Convert a detector finding dict (from ``Finding.to_dict()`` or
        ``TaintFinding.to_dict()``) into a ``RawFinding``.

        The ``engine`` field is set to ``"python"`` (not ``"legacy"``).
        Rule IDs, severity, and evidence are preserved / mapped as described
        in the class docstring.
        """
        vuln_type = old.get("type", "Unknown")
        line = old.get("line", 0)
        if not line:
            return None

        # --- rule_id ---
        rule_id = old.get("rule_id")
        if not rule_id:
            engine_tag = old.get("engine", "unknown")
            safe_type = vuln_type.replace(" ", "_").replace("(", "").replace(")", "")
            rule_id = f"PYTHON_{safe_type.upper()}_{engine_tag.upper()}"

        # --- severity mapping ---
        severity = old.get("severity", "ERROR")
        severity = self._map_severity(severity)

        # --- confidence ---
        confidence = old.get("confidence", "medium")
        if confidence not in ("high", "medium", "low"):
            confidence = "medium"

        # --- message ---
        message = old.get("message") or old.get("detail") or f"Python finding: {vuln_type}"

        # --- evidence ---
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

        # Taint-specific fields (may live in top-level or inside metadata)
        old_metadata = old.get("metadata")
        if old_metadata and isinstance(old_metadata, dict):
            for key in (
                "taint_trace", "source", "sink",
                "source_line", "sink_line",
                "sanitized", "sanitizer",
            ):
                if key in old_metadata:
                    evidence[key] = old_metadata[key]

        # Also check top-level taint fields (TaintFinding.to_dict puts some
        # there directly before the metadata block)
        for key in ("source", "sink", "source_line", "sink_line",
                     "sanitized", "sanitizer"):
            if key in old and key not in evidence:
                evidence[key] = old[key]

        # --- metadata ---
        metadata: dict[str, Any] = {}
        if old_metadata and isinstance(old_metadata, dict):
            for k, v in old_metadata.items():
                if k not in evidence:
                    metadata[k] = v

        # --- cwe ---
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

    # ------------------------------------------------------------------
    # Internal: severity mapping
    # ------------------------------------------------------------------

    @staticmethod
    def _map_severity(severity: str) -> str:
        """
        Map detector severity strings to the standard ``RawFinding`` levels.

        Mapping
        -------
        CRITICAL / ERROR / HIGH  -> ``"ERROR"``
        WARNING / WARN / MEDIUM  -> ``"WARN"``
        LOW / INFO               -> ``"INFO"``
        anything else            -> ``"WARN"``
        """
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
