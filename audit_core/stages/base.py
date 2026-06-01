"""
Base classes for pipeline stages.

Provides the foundation for building modular, testable pipeline stages
that can be developed independently by different team members.

Design Goals:
- Each stage is a self-contained unit with clear input/output
- Stages communicate via PipelineContext (shared state)
- Stages can be extended without modifying the orchestrator
- Error handling is consistent across all stages
"""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any

from audit_core.models import (
    CodeUnit,
    RawFinding,
    AgentHypothesis,
    AgentLog,
    JudgeDecision,
    EvidenceBundle,
    AuditSummary,
    AuditResult,
)

logger = logging.getLogger(__name__)


@dataclass
class PipelineContext:
    """
    Shared context passed between pipeline stages.

    Each stage reads from and writes to this context. The context
    accumulates all data needed to produce the final AuditResult.

    Attributes:
        code_units: Input code units to analyze
        recon_hypotheses: Hypotheses from ReconStage
        raw_findings: Findings from AnalyzerStage (before merge)
        merged_findings: Findings after deduplication
        evidence_bundles: Evidence for each finding
        agent_logs: All agent execution logs
        analyzer_metadata: Analyzer execution info
        stage_results: Per-stage execution results
        metadata: Additional context data
    """

    # Input
    code_units: list[CodeUnit] = field(default_factory=list)

    # Stage outputs
    recon_hypotheses: list[AgentHypothesis] = field(default_factory=list)
    raw_findings: list[RawFinding] = field(default_factory=list)
    merged_findings: list[RawFinding] = field(default_factory=list)
    evidence_bundles: list[EvidenceBundle] = field(default_factory=list)
    agent_logs: list[AgentLog] = field(default_factory=list)

    # Metadata
    analyzer_metadata: dict[str, Any] = field(default_factory=dict)
    stage_results: dict[str, "StageResult"] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)

    # Per-finding intermediate data
    finding_hypotheses: dict[str, list[AgentHypothesis]] = field(default_factory=dict)
    finding_decisions: dict[str, JudgeDecision] = field(default_factory=dict)


@dataclass
class StageResult:
    """
    Result of a single stage execution.

    Records whether the stage succeeded, any errors, and metrics.

    Attributes:
        name: Stage name
        success: Whether the stage completed successfully
        error: Error message if failed
        metrics: Stage-specific metrics (e.g., finding count)
        duration_ms: Execution time in milliseconds
    """

    name: str
    success: bool = True
    error: str | None = None
    metrics: dict[str, Any] = field(default_factory=dict)
    duration_ms: float = 0.0


class BaseStage(ABC):
    """
    Abstract base class for all pipeline stages.

    Each stage implements a single, well-defined transformation
    on the PipelineContext. Stages are executed sequentially.

    To add a new stage:
    1. Create a class inheriting from BaseStage
    2. Implement the `name` property and `run()` method
    3. Register the stage in Pipeline.build_default_pipeline()

    Example:
        class MyStage(BaseStage):
            name = "my_stage"

            def run(self, ctx: PipelineContext) -> StageResult:
                # Process ctx
                ctx.metadata["my_key"] = "my_value"
                return StageResult(name=self.name, success=True)
    """

    name: str = "base"

    @abstractmethod
    def run(self, ctx: PipelineContext) -> StageResult:
        """
        Execute the stage logic.

        Args:
            ctx: Shared pipeline context (read/write)

        Returns:
            StageResult with success status and metrics
        """
        pass

    def __repr__(self) -> str:
        return f"<Stage:{self.name}>"