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
        """
        Generate audit summary and result.

        Args:
            ctx: Pipeline context with all accumulated data

        Returns:
            StageResult with summary metrics
        """
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
                        for name, sr in ctx.stage_results.items()
                    },
                    "analyzer_metadata": ctx.analyzer_metadata,
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