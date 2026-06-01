"""
ReconStage - Initial reconnaissance of code units.

Responsibility:
- Run ReconAgent to identify attack surfaces
- Generate initial hypotheses about potential vulnerabilities
- Record reconnaissance logs

Team Member Assignment: Member 3 (Agent & Knowledge)
"""

from __future__ import annotations

import logging
import time
from typing import TYPE_CHECKING, Any

from audit_core.stages.base import BaseStage, PipelineContext, StageResult

if TYPE_CHECKING:
    from agents.interfaces import ReconAgentBase
    from audit_core.agent_runtime import AgentRuntime

logger = logging.getLogger(__name__)


class ReconStage(BaseStage):
    """
    Reconnaissance stage - identifies attack surfaces.

    Uses ReconAgent to analyze code units and generate initial
    hypotheses about potential vulnerability locations.
    """

    name = "recon"

    def __init__(
        self,
        recon_agent: ReconAgentBase | None = None,
        agent_runtime: AgentRuntime | None = None,
    ) -> None:
        """
        Initialize ReconStage.

        Args:
            recon_agent: The recon agent to use
            agent_runtime: Runtime for error-isolated execution
        """
        self.recon_agent = recon_agent
        self.agent_runtime = agent_runtime

    def run(self, ctx: PipelineContext) -> StageResult:
        """
        Run reconnaissance on code units.

        Args:
            ctx: Pipeline context with code_units

        Returns:
            StageResult with hypothesis count
        """
        start_time = time.time()

        if self.recon_agent is None or self.agent_runtime is None:
            logger.warning("ReconStage: agent or runtime not configured, skipping")
            return StageResult(
                name=self.name,
                success=True,
                metrics={"hypothesis_count": 0, "skipped": True},
            )

        if not ctx.code_units:
            logger.info("ReconStage: no code units to analyze")
            return StageResult(
                name=self.name,
                success=True,
                metrics={"hypothesis_count": 0},
            )

        try:
            result = self.agent_runtime.run_recon(self.recon_agent, ctx.code_units)

            hypotheses = (
                result.output if isinstance(result.output, list) else []
            )
            ctx.recon_hypotheses = hypotheses
            ctx.agent_logs.extend(result.logs)

            duration_ms = (time.time() - start_time) * 1000

            return StageResult(
                name=self.name,
                success=True,
                metrics={
                    "hypothesis_count": len(hypotheses),
                    "log_count": len(result.logs),
                },
                duration_ms=duration_ms,
            )

        except Exception as exc:
            logger.error("ReconStage failed: %s", exc)
            return StageResult(
                name=self.name,
                success=False,
                error=str(exc),
            )