"""
AnalyzerStage - Run static analyzers on code units.

Responsibility:
- Route code units to appropriate analyzers by language
- Execute analyzers and collect raw findings
- Record analyzer metadata

Team Member Assignment: Member 2 (Analyzer & Taint)
"""

from __future__ import annotations

import logging
import time
from typing import TYPE_CHECKING, Any

from audit_core.stages.base import BaseStage, PipelineContext, StageResult

if TYPE_CHECKING:
    from audit_core.registry import AnalyzerRegistry

logger = logging.getLogger(__name__)


class AnalyzerStage(BaseStage):
    """
    Analyzer stage - runs static analysis on code units.

    Routes code units to appropriate analyzers based on language
    and collects all raw findings.
    """

    name = "analyzer"

    def __init__(self, registry: AnalyzerRegistry | None = None) -> None:
        """
        Initialize AnalyzerStage.

        Args:
            registry: Analyzer registry for language routing
        """
        self.registry = registry

    def run(self, ctx: PipelineContext) -> StageResult:
        """
        Run analyzers on code units.

        Args:
            ctx: Pipeline context with code_units

        Returns:
            StageResult with finding count per analyzer
        """
        start_time = time.time()

        if self.registry is None:
            logger.warning("AnalyzerStage: registry not configured, skipping")
            return StageResult(
                name=self.name,
                success=True,
                metrics={"finding_count": 0, "skipped": True},
            )

        if not ctx.code_units:
            logger.info("AnalyzerStage: no code units to analyze")
            return StageResult(
                name=self.name,
                success=True,
                metrics={"finding_count": 0},
            )

        try:
            findings: list[Any] = []
            analyzer_info: dict[str, Any] = {}

            # Group code units by language
            by_language: dict[str, list[Any]] = {}
            for unit in ctx.code_units:
                lang = (unit.language or "unknown").lower()
                by_language.setdefault(lang, []).append(unit)

            # Run analyzers for each language
            for language, units in by_language.items():
                analyzers = self.registry.get_analyzers_for_language(language)
                if not analyzers:
                    logger.debug("No analyzers for language: %s", language)
                    continue

                for analyzer in analyzers:
                    try:
                        analyzer_findings = analyzer.analyze(units)
                        findings.extend(analyzer_findings)
                        analyzer_info[analyzer.name] = {
                            "language": language,
                            "finding_count": len(analyzer_findings),
                            "units_analyzed": len(units),
                        }
                        logger.debug(
                            "Analyzer %s found %d findings for %s",
                            analyzer.name,
                            len(analyzer_findings),
                            language,
                        )
                    except Exception as exc:
                        logger.warning(
                            "Analyzer %s failed for %s: %s",
                            analyzer.name,
                            language,
                            exc,
                        )
                        analyzer_info[analyzer.name] = {
                            "language": language,
                            "error": str(exc),
                        }

            ctx.raw_findings = findings
            ctx.analyzer_metadata = analyzer_info

            duration_ms = (time.time() - start_time) * 1000

            return StageResult(
                name=self.name,
                success=True,
                metrics={
                    "finding_count": len(findings),
                    "analyzers_used": list(analyzer_info.keys()),
                    "languages_processed": list(by_language.keys()),
                },
                duration_ms=duration_ms,
            )

        except Exception as exc:
            logger.error("AnalyzerStage failed: %s", exc)
            return StageResult(
                name=self.name,
                success=False,
                error=str(exc),
            )