"""
Pipeline stages for the audit workflow.

Each stage represents a discrete step in the audit pipeline.
Stages are executed sequentially by the Pipeline executor.

Stage responsibilities are clearly separated to enable:
- Parallel development by different team members
- Independent testing of each stage
- Easy extension with new stages
"""

from audit_core.stages.base import (
    BaseStage,
    PipelineContext,
    StageResult,
)
from audit_core.stages.recon_stage import ReconStage
from audit_core.stages.analyzer_stage import AnalyzerStage
from audit_core.stages.merge_stage import MergeStage
from audit_core.stages.analysis_stage import AnalysisStage
from audit_core.stages.judge_stage import JudgeStage
from audit_core.stages.evidence_stage import EvidenceStage
from audit_core.stages.summary_stage import SummaryStage

__all__ = [
    "BaseStage",
    "PipelineContext",
    "StageResult",
    "ReconStage",
    "AnalyzerStage",
    "MergeStage",
    "AnalysisStage",
    "JudgeStage",
    "EvidenceStage",
    "SummaryStage",
]