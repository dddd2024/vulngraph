"""
EvidenceStage - Build evidence bundles for findings.

Responsibility:
- For each finding with judge decision, build evidence bundle
- Collect code snippets, call chains, and supporting evidence
- Record evidence building logs

Team Member Assignment: Member 3 (Agent & Knowledge)
"""

from __future__ import annotations

import logging
import time
from typing import TYPE_CHECKING, Any

from audit_core.stages.base import BaseStage, PipelineContext, StageResult

if TYPE_CHECKING:
    from audit_core.agent_runtime import AgentRuntime

logger = logging.getLogger(__name__)


class EvidenceStage(BaseStage):
    """
    Evidence stage - builds evidence bundles for findings.

    For each finding with a judge decision, builds an EvidenceBundle
    containing code snippets, call chains, and supporting evidence.
    """

    name = "evidence"

    def __init__(self, agent_runtime: AgentRuntime | None = None) -> None:
        """
        Initialize EvidenceStage.

        Args:
            agent_runtime: Runtime for evidence building
        """
        self.agent_runtime = agent_runtime

    def run(self, ctx: PipelineContext) -> StageResult:
        """
        Build evidence for each adjudicated finding.

        Args:
            ctx: Pipeline context with merged_findings, finding_hypotheses,
                 finding_decisions, and code_units

        Returns:
            StageResult with evidence bundle count
        """
        start_time = time.time()

        if self.agent_runtime is None:
            logger.warning("EvidenceStage: runtime not configured, skipping")
            return StageResult(
                name=self.name,
                success=True,
                metrics={"evidence_count": 0, "skipped": True},
            )

        if not ctx.merged_findings:
            logger.info("EvidenceStage: no findings to build evidence for")
            return StageResult(
                name=self.name,
                success=True,
                metrics={"evidence_count": 0},
            )

        try:
            # Build code_unit lookup by path
            code_unit_by_path: dict[str, Any] = {}
            for unit in ctx.code_units:
                code_unit_by_path[unit.path] = unit

            evidence_bundles: list[Any] = []
            log_count = 0

            for finding in ctx.merged_findings:
                unit = code_unit_by_path.get(finding.file_path)
                hypotheses = ctx.finding_hypotheses.get(finding.id, [])
                decision = ctx.finding_decisions.get(finding.id)

                if decision is None:
                    continue

                result = self.agent_runtime.build_evidence(
                    finding=finding,
                    code_unit=unit,
                    hypotheses=hypotheses,
                    decision=decision,
                    agent_logs=[],  # Logs already collected in previous stages
                )

                bundle = result.output
                if bundle is not None:
                    evidence_bundles.append(bundle)

                log_count += len(result.logs)

            ctx.evidence_bundles = evidence_bundles

            duration_ms = (time.time() - start_time) * 1000

            return StageResult(
                name=self.name,
                success=True,
                metrics={
                    "evidence_count": len(evidence_bundles),
                    "log_count": log_count,
                },
                duration_ms=duration_ms,
            )

        except Exception as exc:
            logger.error("EvidenceStage failed: %s", exc)
            return StageResult(
                name=self.name,
                success=False,
                error=str(exc),
            )