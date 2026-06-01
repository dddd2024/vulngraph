"""
JudgeStage - Run JudgeAgent to adjudicate findings.

Responsibility:
- For each finding with hypotheses, run JudgeAgent
- Produce verdict (confirmed/suspicious/rejected)
- Calculate risk score

Team Member Assignment: Member 3 (Agent & Knowledge)
"""

from __future__ import annotations

import logging
import time
from typing import TYPE_CHECKING, Any

from audit_core.stages.base import BaseStage, PipelineContext, StageResult

if TYPE_CHECKING:
    from agents.interfaces import JudgeAgentBase
    from audit_core.agent_runtime import AgentRuntime

logger = logging.getLogger(__name__)


class JudgeStage(BaseStage):
    """
    Judge stage - adjudicates findings and calculates risk.

    For each finding with analysis hypotheses, runs JudgeAgent
    to produce a verdict and risk score.
    """

    name = "judge"

    def __init__(
        self,
        judge_agent: JudgeAgentBase | None = None,
        agent_runtime: AgentRuntime | None = None,
    ) -> None:
        """
        Initialize JudgeStage.

        Args:
            judge_agent: The judge agent to use
            agent_runtime: Runtime for error-isolated execution
        """
        self.judge_agent = judge_agent
        self.agent_runtime = agent_runtime

    def run(self, ctx: PipelineContext) -> StageResult:
        """
        Run judgment on each finding.

        Args:
            ctx: Pipeline context with merged_findings and finding_hypotheses

        Returns:
            StageResult with decision count and verdict breakdown
        """
        start_time = time.time()

        if self.judge_agent is None or self.agent_runtime is None:
            logger.warning("JudgeStage: agent or runtime not configured, skipping")
            return StageResult(
                name=self.name,
                success=True,
                metrics={"decision_count": 0, "skipped": True},
            )

        if not ctx.merged_findings:
            logger.info("JudgeStage: no findings to judge")
            return StageResult(
                name=self.name,
                success=True,
                metrics={"decision_count": 0},
            )

        try:
            decisions_by_finding: dict[str, Any] = {}
            verdict_counts: dict[str, int] = {"confirmed": 0, "suspicious": 0, "rejected": 0}
            log_count = 0

            for finding in ctx.merged_findings:
                hypotheses = ctx.finding_hypotheses.get(finding.id, [])

                result = self.agent_runtime.run_judge(
                    self.judge_agent, finding, hypotheses
                )

                decision = result.output
                if decision is not None:
                    decisions_by_finding[finding.id] = decision
                    verdict = decision.verdict
                    if verdict in verdict_counts:
                        verdict_counts[verdict] += 1

                log_count += len(result.logs)
                ctx.agent_logs.extend(result.logs)

            ctx.finding_decisions = decisions_by_finding

            duration_ms = (time.time() - start_time) * 1000

            return StageResult(
                name=self.name,
                success=True,
                metrics={
                    "decision_count": len(decisions_by_finding),
                    "verdict_breakdown": verdict_counts,
                    "log_count": log_count,
                },
                duration_ms=duration_ms,
            )

        except Exception as exc:
            logger.error("JudgeStage failed: %s", exc)
            return StageResult(
                name=self.name,
                success=False,
                error=str(exc),
            )