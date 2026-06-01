"""
SummaryStage - Generate audit summary.

Responsibility:
- Calculate total findings, evidence bundles, risk score
- Generate AuditSummary
- Produce final AuditResult

Team Member Assignment: Member 1 (Core & Orchestrator)
"""

from __future__ import annotations

import logging
import time
from typing import Any

from audit_core.models import AuditSummary, AuditResult
from audit_core.stages.base import BaseStage, PipelineContext, StageResult

logger = logging.getLogger(__name__)


class SummaryStage(BaseStage):
    """
    Summary stage - generates the final audit result.

    Aggregates all findings, evidence, and logs into an AuditResult
    with a comprehensive AuditSummary.
    """

    name = "summary"

    def run(self, ctx: PipelineContext) -> StageResult:
        start_time = time.time()

        try:
            # Calculate risk score from judge decisions
            total_risk = 0.0
            confirmed_count = 0
            suspicious_count = 0
            rejected_count = 0

            for decision in ctx.finding_decisions.values():
                total_risk += decision.risk_score or 0
                verdict = decision.verdict
                if verdict == "confirmed":
                    confirmed_count += 1
                elif verdict == "suspicious":
                    suspicious_count += 1
                elif verdict == "rejected":
                    rejected_count += 1

            # Calculate average risk (0-100 scale)
            decision_count = len(ctx.finding_decisions)
            avg_risk = total_risk / decision_count if decision_count > 0 else 0.0

            # Collect languages and files
            languages: set[str] = set()
            scanned_files: list[str] = []
            for unit in ctx.code_units:
                if unit.language:
                    languages.add(unit.language.lower())
                scanned_files.append(unit.path)

            # Build summary
            summary = AuditSummary(
                total_code_units=len(ctx.code_units),
                total_findings=len(ctx.merged_findings),
                total_evidence_bundles=len(ctx.evidence_bundles),
                risk_score=round(avg_risk, 1),
                languages=list(languages),
                scanned_files=scanned_files,
            )

            # Build this stage's own result (for inclusion in stage_results)
            this_stage_result = StageResult(
                name=self.name,
                success=True,
                metrics={
                    "total_findings": len(ctx.merged_findings),
                    "total_evidence": len(ctx.evidence_bundles),
                    "risk_score": round(avg_risk, 1),
                    "confirmed": confirmed_count,
                    "suspicious": suspicious_count,
                    "rejected": rejected_count,
                },
                duration_ms=(time.time() - start_time) * 1000,
            )

            # Build stage_results dict including this stage
            all_stage_results = dict(ctx.stage_results)
            all_stage_results[self.name] = this_stage_result

            # Build final result
            result = AuditResult(
                summary=summary,
                findings=ctx.merged_findings,
                evidence=ctx.evidence_bundles,
                agent_logs=ctx.agent_logs,
                metadata={
                    "stage_results": {
                        name: {
                            "success": sr.success,
                            "metrics": sr.metrics,
                            "duration_ms": sr.duration_ms,
                        }
                        for name, sr in all_stage_results.items()
                    },
                    "analyzer_metadata": ctx.analyzer_metadata,
                    # Backward compatibility: old API endpoints expect this format
                    "analyzer_info": self._build_analyzer_info(ctx.analyzer_metadata),
                    "verdict_breakdown": {
                        "confirmed": confirmed_count,
                        "suspicious": suspicious_count,
                        "rejected": rejected_count,
                    },
                },
            )

            # Store result in context
            ctx.metadata["audit_result"] = result

            duration_ms = (time.time() - start_time) * 1000

            return StageResult(
                name=self.name,
                success=True,
                metrics={
                    "total_findings": len(ctx.merged_findings),
                    "total_evidence": len(ctx.evidence_bundles),
                    "risk_score": round(avg_risk, 1),
                    "confirmed": confirmed_count,
                    "suspicious": suspicious_count,
                    "rejected": rejected_count,
                },
                duration_ms=duration_ms,
            )

        except Exception as exc:
            logger.error("SummaryStage failed: %s", exc)
            return StageResult(
                name=self.name,
                success=False,
                error=str(exc),
            )

    @staticmethod
    def _build_analyzer_info(analyzer_metadata: dict) -> dict:
        """
        Convert analyzer_metadata (dict keyed by analyzer name) to the
        legacy analyzer_info format expected by old API endpoints.

        Args:
            analyzer_metadata: Dict of {analyzer_name: {language, finding_count, ...}}

        Returns:
            Dict with keys: analyzer_runs, analyzer_errors, skipped_languages
        """
        analyzer_runs = []
        analyzer_errors = []
        skipped_languages = []

        for name, info in analyzer_metadata.items():
            if isinstance(info, dict):
                if "error" in info:
                    analyzer_errors.append({
                        "analyzer": name,
                        "analyzer_name": name,
                        "success": False,
                        "error": info["error"],
                        "language": info.get("language"),
                    })
                else:
                    analyzer_runs.append({
                        "analyzer": name,
                        "analyzer_name": name,
                        "success": True,
                        "language": info.get("language"),
                        "finding_count": info.get("finding_count", 0),
                        "units_analyzed": info.get("units_analyzed", 0),
                    })

        return {
            "analyzer_runs": analyzer_runs,
            "analyzer_errors": analyzer_errors,
            "skipped_languages": skipped_languages,
        }