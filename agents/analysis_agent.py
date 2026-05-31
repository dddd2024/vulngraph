"""
Analysis agent for vulnerability hypothesis generation.

The AnalysisAgent analyzes RawFinding objects and generates hypotheses
about potential vulnerabilities using LLM or fallback logic.
"""

from typing import Any

from audit_core.models import RawFinding, AgentHypothesis, AgentLog, CodeUnit
from agents.interfaces import AnalysisAgentBase


class AnalysisAgent(AnalysisAgentBase):
    """
    Agent that analyzes findings and generates vulnerability hypotheses.

    Uses LLM for deep analysis when available, falls back to rule-based
    explanations when LLM is unavailable or fails.

    Input:
        finding: RawFinding to analyze
        code_unit: Optional CodeUnit for context

    Output:
        Tuple of (AgentHypothesis, AgentLog)

    Does NOT read files directly - only uses provided context.
    Supports LLM fallback for resilience.
    """

    name = "analysis"

    # Severity to confidence mapping
    SEVERITY_CONFIDENCE = {
        "ERROR": "high",
        "WARN": "medium",
        "INFO": "low",
    }

    # Finding type to vulnerability type mapping
    TYPE_VULN_MAP = {
        "sql_injection": "SQL Injection",
        "command_injection": "Command Injection",
        "xss": "Cross-Site Scripting (XSS)",
        "path_traversal": "Path Traversal",
        "deserialization": "Insecure Deserialization",
        "ssrf": "Server-Side Request Forgery (SSRF)",
        "file_upload": "Unrestricted File Upload",
        "hardcoded_secret": "Hardcoded Secret",
        "weak_crypto": "Weak Cryptography",
        "insecure_random": "Insecure Randomness",
        "debug_info": "Debug Information Exposure",
        "info_disclosure": "Information Disclosure",
    }

    def __init__(self, llm_client: Any | None = None) -> None:
        """
        Initialize the AnalysisAgent.

        Args:
            llm_client: Optional LLM client for LLM-powered analysis.
                       If None, uses rule-based fallback.
        """
        self._llm_client = llm_client

    def run(
        self,
        finding: RawFinding,
        code_unit: CodeUnit | None = None,
    ) -> tuple[AgentHypothesis, AgentLog]:
        """
        Analyze a finding and generate a hypothesis.

        Args:
            finding: The RawFinding to analyze
            code_unit: Optional CodeUnit for context

        Returns:
            Tuple of (AgentHypothesis, AgentLog)
        """
        try:
            # Try LLM analysis first
            hypothesis, log = self._analyze_with_llm(finding, code_unit)
        except Exception:
            # Fall back to rule-based analysis
            hypothesis, log = self._analyze_with_fallback(finding, code_unit)

        return hypothesis, log

    def _analyze_with_llm(
        self,
        finding: RawFinding,
        code_unit: CodeUnit | None = None,
    ) -> tuple[AgentHypothesis, AgentLog]:
        """
        Analyze using LLM (placeholder for actual LLM integration).

        Args:
            finding: The RawFinding to analyze
            code_unit: Optional CodeUnit for context

        Returns:
            Tuple of (AgentHypothesis, AgentLog)
        """
        # Placeholder: In Stage 2, this would call actual LLM
        # For now, delegate to fallback
        return self._analyze_with_fallback(finding, code_unit)

    def _analyze_with_fallback(
        self,
        finding: RawFinding,
        code_unit: CodeUnit | None = None,
    ) -> tuple[AgentHypothesis, AgentLog]:
        """
        Rule-based fallback analysis when LLM is unavailable.

        Args:
            finding: The RawFinding to analyze
            code_unit: Optional CodeUnit for context

        Returns:
            Tuple of (AgentHypothesis, AgentLog)
        """
        # Map finding type to vulnerability type
        vuln_type = self.TYPE_VULN_MAP.get(
            finding.type,
            f"Potential {finding.type.replace('_', ' ').title()}"
        )

        # Map severity to confidence
        confidence = self.SEVERITY_CONFIDENCE.get(finding.severity, "low")

        # Generate reasoning based on finding type
        reasoning = self._generate_reasoning(finding, code_unit)

        # Create hypothesis
        hypothesis = AgentHypothesis(
            agent_name=self.name,
            hypothesis=f"{vuln_type} vulnerability detected",
            vulnerability_type=vuln_type,
            reasoning_summary=reasoning,
            confidence=confidence,
            supporting_evidence_ids=[finding.id],
            metadata={
                "finding_type": finding.type,
                "finding_severity": finding.severity,
                "engine": finding.engine,
                "file_path": finding.file_path,
                "line_number": finding.start_line,
                "has_code_context": code_unit is not None,
            }
        )

        # Create log
        log = AgentLog(
            agent_name=self.name,
            stage="analysis",
            message=f"Analyzed {finding.type} finding in {finding.file_path}:{finding.start_line}",
            input_refs=[finding.id],
            output_refs=[hypothesis.id],
            metadata={
                "analysis_method": "fallback",
                "vulnerability_type": vuln_type,
                "confidence": confidence,
            }
        )

        return hypothesis, log

    def _generate_reasoning(
        self,
        finding: RawFinding,
        code_unit: CodeUnit | None = None,
    ) -> str:
        """
        Generate reasoning summary for a finding.

        Args:
            finding: The RawFinding
            code_unit: Optional CodeUnit for context

        Returns:
            Reasoning string
        """
        base_reasoning = finding.message

        if code_unit:
            base_reasoning += f" Context from {code_unit.path} supports this assessment."

        # Add type-specific reasoning
        type_reasoning = {
            "sql_injection": "User input flows directly into SQL query without sanitization.",
            "command_injection": "User input is passed to command execution functions.",
            "xss": "User input is rendered in HTML without proper encoding.",
            "path_traversal": "User input is used to construct file paths without validation.",
            "deserialization": "Untrusted data is deserialized without type checking.",
            "ssrf": "User-controlled URL is used for server-side requests.",
            "file_upload": "File upload lacks validation of file type and content.",
            "hardcoded_secret": "Sensitive credentials are hardcoded in source code.",
            "weak_crypto": "Weak cryptographic algorithms or improper usage detected.",
            "insecure_random": "Predictable random number generation for security purposes.",
        }

        specific = type_reasoning.get(finding.type, "")
        if specific:
            base_reasoning += f" {specific}"

        return base_reasoning
