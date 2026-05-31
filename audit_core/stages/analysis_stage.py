"""
AnalysisStage - Run AnalysisAgent on each finding.

Responsibility:
- For each merged finding, run AnalysisAgent
- Generate vulnerability hypotheses
- Record analysis logs

Team Member Assignment: Member 3 (Agent & Knowledge)
"""

from __future__ import annotations

import logging
import time
from typing import TYPE_CHECKING, Any

from audit_core.stages.base import BaseStage, PipelineContext, StageResult

if TYPE_CHECKING:
    from agents.interfaces import AnalysisAgentBase
    from audit_core.agent_runtime import AgentRuntime

logger = logging.getLogger(__name__)


class AnalysisStage(BaseStage):
    """
    Analysis stage - generates vulnerability hypotheses.

    For each merged finding, runs AnalysisAgent to produce
    detailed hypotheses about the vulnerability.
    """

    name = "analysis"

    def __init__(
        self,
        analysis_agent: AnalysisAgentBase | None = None,
        agent_runtime: AgentRuntime | None = None,
    ) -> None:
        """
        Initialize AnalysisStage.

        Args:
            analysis_agent: The analysis agent to use
            agent_runtime: Runtime for error-isolated execution
        """
        self.analysis_agent = analysis_agent
        self.agent_runtime = agent_runtime

    def run(self, ctx: PipelineContext) -> StageResult:
        """
        Run analysis on each merged finding.

        Args:
            ctx: Pipeline context with merged_findings and code_units

        Returns:
            StageResult with hypothesis count
        """
        start_time = time.time()

        if self.analysis_agent is None or self.agent_runtime is None:
            logger.warning("AnalysisStage: agent or runtime not configured, skipping")
            return StageResult(
                name=self.name,
                success=True,
                metrics={"hypothesis_count": 0, "skipped": True},
            )

        if not ctx.merged_findings:
            logger.info("AnalysisStage: no findings to analyze")
            return StageResult(
                name=self.name,
                success=True,
                metrics={"hypothesis_count": 0},
            )

        try:
            # Build code_unit lookup by path
            code_unit_by_path: dict[str, Any] = {}
            for unit in ctx.code_units:
                code_unit_by_path[unit.path] = unit

            hypotheses_by_finding: dict[str, list[Any]] = {}
            total_hypotheses = 0
            log_count = 0

            for finding in ctx.merged_findings:
                # Find associated code unit
                unit = code_unit_by_path.get(finding.file_path)

                result = self.agent_runtime.run_analysis(
                    self.analysis_agent, finding, code_unit=unit
                )

                hypothesis = result.output
                if hypothesis is not None:
                    finding_id = finding.id
                    hypotheses_by_finding[finding_id] = [hypothesis]
                    total_hypotheses += 1

                log_count += len(result.logs)
                ctx.agent_logs.extend(result.logs)

            ctx.finding_hypotheses = hypotheses_by_finding

            duration_ms = (time.time() - start_time) * 1000

            return StageResult(
                name=self.name,
                success=True,
                metrics={
                    "hypothesis_count": total_hypotheses,
                    "findings_analyzed": len(ctx.merged_findings),
                    "log_count": log_count,
                },
                duration_ms=duration_ms,
            )

        except Exception as exc:
            logger.error("AnalysisStage failed: %s", exc)
            return StageResult(
                name=self.name,
                success=False,
                error=str(exc),
            )