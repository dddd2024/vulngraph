"""
Agent runtime module for error-isolated Agent execution.

This module provides the AgentRuntime class that wraps Agent calls
with error isolation, degradation recovery, and structured logging.
When Agents fail, the runtime applies fallback strategies from ErrorPolicy
rather than letting exceptions propagate and crash the entire scan.
"""

from typing import Any

from audit_core.models import (
    CodeUnit, RawFinding, AgentHypothesis,
    JudgeDecision, AgentLog, EvidenceBundle
)
from audit_core.error_policy import ErrorPolicy, AgentExecutionResult
from agents.recon_agent import ReconAgent
from agents.analysis_agent import AnalysisAgent
from agents.judge_agent import JudgeAgent
from evidence.evidence_builder import build_evidence_bundle


class AgentRuntime:
    """
    Runtime for executing Agents with error isolation and fallback handling.

    The AgentRuntime wraps Agent calls and ensures that:
    1. Exceptions are caught and don't crash the entire scan
    2. Structured logs are generated for both success and failure cases
    3. Fallback outputs are generated when Agents fail
    4. The audit flow continues even when individual Agents fail

    Usage:
        runtime = AgentRuntime()

        # Run recon agent
        result = runtime.run_recon(recon_agent, code_units)
        hypotheses = result.output if result.status in ("success", "failed") else []
        logs.extend(result.logs)

        # Run analysis agent
        result = runtime.run_analysis(analysis_agent, finding, code_unit)
        hypothesis = result.output if result.status in ("success", "degraded") else None
        logs.extend(result.logs)

        # Run judge agent
        result = runtime.run_judge(judge_agent, finding, hypotheses, evidence_bundle)
        decision = result.output if result.status in ("success", "degraded") else None
        logs.extend(result.logs)
    """

    def __init__(self) -> None:
        """Initialize the AgentRuntime."""
        self.error_policy = ErrorPolicy()

    def run_recon(
        self,
        agent: ReconAgent,
        code_units: list[CodeUnit]
    ) -> AgentExecutionResult:
        """
        Run the ReconAgent with error isolation.

        If the agent fails, returns an empty hypotheses list and logs
        the failure. The audit flow continues.

        Args:
            agent: The ReconAgent instance to run
            code_units: List of code units to analyze

        Returns:
            AgentExecutionResult with hypotheses list and logs
        """
        try:
            # Attempt to run the agent
            hypotheses, logs = agent.run(code_units)

            # Create success result
            success_log = ErrorPolicy.create_success_log(
                agent_name="recon",
                stage="recon",
                message=f"ReconAgent successfully analyzed {len(code_units)} code units, "
                        f"generated {len(hypotheses)} hypotheses.",
                input_refs=[unit.id for unit in code_units],
                output_refs=[h.id for h in hypotheses],
                metadata={
                    "code_unit_count": len(code_units),
                    "hypothesis_count": len(hypotheses),
                    "status": "success"
                }
            )

            return AgentExecutionResult(
                status="success",
                output=hypotheses,
                logs=logs + [success_log],
                error=None,
                fallback_used=False,
                stage="recon",
                agent_name="recon"
            )

        except Exception as exc:
            # Agent failed - apply fallback strategy
            return ErrorPolicy.create_fallback_recon_result(
                code_unit_count=len(code_units),
                error=exc
            )

    def run_analysis(
        self,
        agent: AnalysisAgent,
        finding: RawFinding,
        code_unit: CodeUnit | None
    ) -> AgentExecutionResult:
        """
        Run the AnalysisAgent with error isolation.

        If the agent fails, generates a fallback hypothesis with low
        confidence and logs the failure. The audit flow continues.

        Args:
            agent: The AnalysisAgent instance to run
            finding: The finding to analyze
            code_unit: Optional code unit for context

        Returns:
            AgentExecutionResult with hypothesis and logs
        """
        try:
            # Attempt to run the agent
            hypothesis, log = agent.run(finding, code_unit)

            # Create success result
            return AgentExecutionResult(
                status="success",
                output=hypothesis,
                logs=[log],
                error=None,
                fallback_used=False,
                stage="analysis",
                agent_name="analysis"
            )

        except Exception as exc:
            # Agent failed - apply fallback strategy
            return ErrorPolicy.create_fallback_analysis_result(
                finding_id=finding.id,
                finding_type=finding.type,
                error=exc
            )

    def run_judge(
        self,
        agent: JudgeAgent,
        finding: RawFinding,
        hypotheses: list[AgentHypothesis],
        evidence_bundle: EvidenceBundle | None = None
    ) -> AgentExecutionResult:
        """
        Run the JudgeAgent with error isolation.

        If the agent fails, generates a fallback JudgeDecision with:
        - verdict = "suspicious"
        - confidence = "low"
        - risk_score = 30 (conservative value)

        Args:
            agent: The JudgeAgent instance to run
            finding: The finding to evaluate
            hypotheses: List of hypotheses to consider
            evidence_bundle: Optional evidence bundle

        Returns:
            AgentExecutionResult with JudgeDecision and logs
        """
        try:
            # Attempt to run the agent
            decision, log = agent.run(finding, hypotheses, evidence_bundle)

            # Create success result
            return AgentExecutionResult(
                status="success",
                output=decision,
                logs=[log],
                error=None,
                fallback_used=False,
                stage="judge",
                agent_name="judge"
            )

        except Exception as exc:
            # Agent failed - apply fallback strategy
            return ErrorPolicy.create_fallback_judge_result(
                finding_id=finding.id,
                error=exc
            )

    def build_evidence(
        self,
        finding: RawFinding,
        code_unit: CodeUnit | None,
        hypotheses: list[AgentHypothesis],
        agent_logs: list[AgentLog],
        judge_decision: JudgeDecision | None
    ) -> tuple[EvidenceBundle | None, list[AgentLog]]:
        """
        Build evidence bundle with error isolation.

        If evidence building fails, returns None and logs the failure.
        The finding is still preserved in the audit result.

        Args:
            finding: The vulnerability finding
            code_unit: Optional code unit containing the finding
            hypotheses: List of agent hypotheses
            agent_logs: List of agent execution logs
            judge_decision: Optional judge decision

        Returns:
            Tuple of (EvidenceBundle or None, additional_logs)
        """
        try:
            # Attempt to build evidence bundle
            evidence = build_evidence_bundle(
                finding=finding,
                code_unit=code_unit,
                hypotheses=hypotheses,
                agent_logs=agent_logs,
                judge_decision=judge_decision
            )

            return evidence, []

        except Exception as exc:
            # Evidence building failed - log and continue
            failure_log = ErrorPolicy.create_evidence_failure_log(
                finding_id=finding.id,
                error=exc
            )

            return None, [failure_log]

    def run_analysis_batch(
        self,
        agent: AnalysisAgent,
        findings: list[RawFinding],
        code_units: list[CodeUnit]
    ) -> list[AgentExecutionResult]:
        """
        Run AnalysisAgent on a batch of findings with error isolation.

        Each finding is processed independently - failures in one finding
        do not affect others.

        Args:
            agent: The AnalysisAgent instance to run
            findings: List of findings to analyze
            code_units: List of code units for context lookup

        Returns:
            List of AgentExecutionResult, one per finding
        """
        results = []

        for finding in findings:
            # Find corresponding code unit
            code_unit = self._find_code_unit(code_units, finding.file_path)

            # Run analysis with error isolation
            result = self.run_analysis(agent, finding, code_unit)
            results.append(result)

        return results

    def run_judge_batch(
        self,
        agent: JudgeAgent,
        findings: list[RawFinding],
        hypotheses_map: dict[str, list[AgentHypothesis]],
        evidence_map: dict[str, EvidenceBundle] | None = None
    ) -> list[AgentExecutionResult]:
        """
        Run JudgeAgent on a batch of findings with error isolation.

        Each finding is judged independently - failures in one finding
        do not affect others.

        Args:
            agent: The JudgeAgent instance to run
            findings: List of findings to judge
            hypotheses_map: Map of finding_id -> list of hypotheses
            evidence_map: Optional map of finding_id -> evidence bundle

        Returns:
            List of AgentExecutionResult, one per finding
        """
        results = []
        evidence_map = evidence_map or {}

        for finding in findings:
            # Get hypotheses for this finding
            hypotheses = hypotheses_map.get(finding.id, [])

            # Get evidence for this finding
            evidence = evidence_map.get(finding.id)

            # Run judge with error isolation
            result = self.run_judge(agent, finding, hypotheses, evidence)
            results.append(result)

        return results

    @staticmethod
    def _find_code_unit(
        code_units: list[CodeUnit],
        file_path: str
    ) -> CodeUnit | None:
        """
        Find a code unit by file path.

        Args:
            code_units: List of code units to search
            file_path: Path to find

        Returns:
            Matching CodeUnit or None
        """
        for unit in code_units:
            if unit.path == file_path or unit.path.endswith(file_path):
                return unit
        return None

    def extract_outputs(
        self,
        results: list[AgentExecutionResult]
    ) -> list[Any]:
        """
        Extract output values from a list of execution results.

        Filters out None outputs and returns a flat list of outputs.

        Args:
            results: List of AgentExecutionResult

        Returns:
            List of output values (excluding None)
        """
        outputs = []
        for result in results:
            if result.output is not None:
                if isinstance(result.output, list):
                    outputs.extend(result.output)
                else:
                    outputs.append(result.output)
        return outputs

    def collect_logs(
        self,
        results: list[AgentExecutionResult]
    ) -> list[AgentLog]:
        """
        Collect all logs from a list of execution results.

        Args:
            results: List of AgentExecutionResult

        Returns:
            Flat list of all AgentLog entries
        """
        logs = []
        for result in results:
            logs.extend(result.logs)
        return logs
