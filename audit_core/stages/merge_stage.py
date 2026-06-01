"""
MergeStage - Deduplicate and merge findings.

Responsibility:
- Deduplicate findings from multiple analyzers
- Apply result merging logic
- Produce merged_findings list

Team Member Assignment: Member 1 (Core & Orchestrator)
"""

from __future__ import annotations

import logging
import time

from audit_core.stages.base import BaseStage, PipelineContext, StageResult
from audit_core.result_merger import merge_findings

logger = logging.getLogger(__name__)


class MergeStage(BaseStage):
    """
    Merge stage - deduplicates and merges findings.

    Takes raw_findings from multiple analyzers and produces
    a deduplicated merged_findings list.
    """

    name = "merge"

    def run(self, ctx: PipelineContext) -> StageResult:
        """
        Merge findings from analyzers.

        Args:
            ctx: Pipeline context with raw_findings

        Returns:
            StageResult with merged finding count
        """
        start_time = time.time()

        if not ctx.raw_findings:
            logger.info("MergeStage: no findings to merge")
            ctx.merged_findings = []
            return StageResult(
                name=self.name,
                success=True,
                metrics={"merged_count": 0, "original_count": 0},
            )

        try:
            merged = merge_findings(ctx.raw_findings)
            ctx.merged_findings = merged

            duration_ms = (time.time() - start_time) * 1000

            return StageResult(
                name=self.name,
                success=True,
                metrics={
                    "merged_count": len(merged),
                    "original_count": len(ctx.raw_findings),
                    "dedup_count": len(ctx.raw_findings) - len(merged),
                },
                duration_ms=duration_ms,
            )

        except Exception as exc:
            logger.error("MergeStage failed: %s", exc)
            return StageResult(
                name=self.name,
                success=False,
                error=str(exc),
            )