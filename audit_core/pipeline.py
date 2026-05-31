"""
Pipeline executor for the audit workflow.

The Pipeline class orchestrates the execution of all stages in sequence.
It provides a clean separation between the orchestrator's coordination
logic and the actual stage implementations.

Design Goals:
- AuditOrchestrator delegates to Pipeline for stage execution
- Each stage can be developed independently
- New stages can be added without modifying the orchestrator
- Pipeline can be extended or customized for different workflows

Team Member Assignment: Member 1 (Core & Orchestrator)
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

from audit_core.stages.base import BaseStage, PipelineContext, StageResult
from audit_core.stages.recon_stage import ReconStage
from audit_core.stages.analyzer_stage import AnalyzerStage
from audit_core.stages.merge_stage import MergeStage
from audit_core.stages.analysis_stage import AnalysisStage
from audit_core.stages.judge_stage import JudgeStage
from audit_core.stages.evidence_stage import EvidenceStage
from audit_core.stages.summary_stage import SummaryStage
from audit_core.models import AuditResult

if TYPE_CHECKING:
    from audit_core.registry import AnalyzerRegistry
    from agents.registry import AgentRegistry
    from audit_core.agent_runtime import AgentRuntime

logger = logging.getLogger(__name__)


class Pipeline:
    """
    Pipeline executor that runs stages in sequence.

    The pipeline is responsible for:
    - Executing stages in order
    - Passing context between stages
    - Recording stage results
    - Returning the final AuditResult

    Example:
        pipeline = Pipeline.build_default_pipeline(
            analyzer_registry=registry,
            agent_registry=agent_reg,
            agent_runtime=runtime,
        )
        result = pipeline.run(code_units)
    """

    def __init__(self, stages: list[BaseStage] | None = None) -> None:
        """
        Initialize Pipeline with optional custom stages.

        Args:
            stages: List of stages to execute (can be empty for custom setup)
        """
        self.stages: list[BaseStage] = stages or []

    def add_stage(self, stage: BaseStage) -> None:
        """Add a stage to the pipeline."""
        self.stages.append(stage)

    def run(self, code_units: list[Any]) -> AuditResult:
        """
        Execute all stages and return the audit result.

        Args:
            code_units: List of CodeUnit objects to analyze

        Returns:
            AuditResult with summary, findings, evidence, and logs
        """
        ctx = PipelineContext(code_units=code_units)

        for stage in self.stages:
            logger.info("Running stage: %s", stage.name)
            result = stage.run(ctx)
            ctx.stage_results[stage.name] = result

            if not result.success:
                logger.warning("Stage %s failed: %s", stage.name, result.error)
                # Continue with remaining stages (graceful degradation)

        # Get the final result from SummaryStage
        audit_result = ctx.metadata.get("audit_result")

        if audit_result is None:
            # Fallback: build minimal result
            from audit_core.models import AuditSummary
            audit_result = AuditResult(
                summary=AuditSummary(
                    total_code_units=len(code_units),
                    total_findings=len(ctx.merged_findings),
                    total_evidence_bundles=len(ctx.evidence_bundles),
                    risk_score=0.0,
                    languages=[],
                    scanned_files=[u.path for u in code_units],
                ),
                findings=ctx.merged_findings,
                evidence=ctx.evidence_bundles,
                agent_logs=ctx.agent_logs,
            )

        return audit_result

    @classmethod
    def build_default_pipeline(
        cls,
        analyzer_registry: AnalyzerRegistry | None = None,
        agent_registry: AgentRegistry | None = None,
        agent_runtime: AgentRuntime | None = None,
    ) -> "Pipeline":
        """
        Build the default audit pipeline with all standard stages.

        The default pipeline includes:
        1. ReconStage - Initial reconnaissance
        2. AnalyzerStage - Static analysis
        3. MergeStage - Finding deduplication
        4. AnalysisStage - Vulnerability hypothesis generation
        5. JudgeStage - Finding adjudication
        6. EvidenceStage - Evidence bundle building
        7. SummaryStage - Result aggregation

        Args:
            analyzer_registry: Registry for analyzers
            agent_registry: Registry for agents
            agent_runtime: Runtime for agent execution

        Returns:
            Configured Pipeline instance
        """
        pipeline = cls()

        # Get agents from registry if available
        recon_agent = None
        analysis_agent = None
        judge_agent = None

        if agent_registry is not None:
            recon_agent = agent_registry.get_recon()
            analysis_agent = agent_registry.get_analysis()
            judge_agent = agent_registry.get_judge()

        # Add stages in order
        pipeline.add_stage(ReconStage(
            recon_agent=recon_agent,
            agent_runtime=agent_runtime,
        ))
        pipeline.add_stage(AnalyzerStage(registry=analyzer_registry))
        pipeline.add_stage(MergeStage())
        pipeline.add_stage(AnalysisStage(
            analysis_agent=analysis_agent,
            agent_runtime=agent_runtime,
        ))
        pipeline.add_stage(JudgeStage(
            judge_agent=judge_agent,
            agent_runtime=agent_runtime,
        ))
        pipeline.add_stage(EvidenceStage(agent_runtime=agent_runtime))
        pipeline.add_stage(SummaryStage())

        return pipeline