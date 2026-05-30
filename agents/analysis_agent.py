"""
Analysis agent for generating vulnerability hypotheses.

The AnalysisAgent analyzes findings and generates hypotheses about
potential vulnerabilities. It can use LLM clients for enhanced analysis
or fall back to rule-based explanations when no LLM is available.
"""

from audit_core.models import CodeUnit, RawFinding, AgentHypothesis, AgentLog
from agents.base_agent import BaseAgent
from llm.base import LLMClientBase
from llm.mock_client import MockLLMClient
from llm.prompt_templates import build_vulnerability_explanation_prompt


class AnalysisAgent(BaseAgent):
    """
    Agent that analyzes findings and generates hypotheses.
    
    Supports two modes:
    1. LLM mode: Uses provided LLM client for detailed analysis
    2. Fallback mode: Uses rule-based explanations when no LLM available
    
    This ensures tests can run without real API keys by using MockLLMClient.
    """
    
    name = "analysis"
    
    def __init__(self, llm_client: LLMClientBase | None = None) -> None:
        """
        Initialize AnalysisAgent.
        
        Args:
            llm_client: LLM client for enhanced analysis (optional)
                        If None, uses rule-based fallback
        """
        self._llm_client = llm_client
    
    def run(
        self,
        finding: RawFinding,
        code_unit: CodeUnit | None = None
    ) -> tuple[AgentHypothesis, AgentLog]:
        """
        Analyze a finding and generate a hypothesis.
        
        Args:
            finding: The finding to analyze
            code_unit: Optional code unit containing the finding
            
        Returns:
            Tuple of (hypothesis, log)
        """
        # Determine analysis method
        if self._llm_client and self._llm_client.is_available():
            explanation = self._analyze_with_llm(finding, code_unit)
            analysis_method = "llm"
        else:
            explanation = self._generate_fallback_explanation(finding)
            analysis_method = "fallback"
        
        hypothesis = AgentHypothesis(
            agent_name=self.name,
            finding_id=finding.id,
            hypothesis=f"Potential {finding.type} vulnerability detected.",
            vulnerability_type=finding.type,
            reasoning_summary=explanation,
            confidence=finding.confidence,
            supporting_evidence_ids=[finding.id],
            metadata={
                "analysis_method": analysis_method,
                "cwe": finding.cwe,
            }
        )
        
        log = AgentLog(
            agent_name=self.name,
            stage="analysis",
            message=f"AnalysisAgent analyzed finding {finding.id} of type {finding.type} using {analysis_method}.",
            input_refs=[finding.id, code_unit.id if code_unit else None],
            output_refs=[hypothesis.id],
            metadata={
                "analysis_method": analysis_method,
                "llm_provider": self._llm_client.provider_name if self._llm_client else None,
            }
        )
        
        return hypothesis, log
    
    def _analyze_with_llm(
        self,
        finding: RawFinding,
        code_unit: CodeUnit | None
    ) -> str:
        """
        Analyze finding using LLM client.
        
        Args:
            finding: The finding to analyze
            code_unit: Optional code unit for context
            
        Returns:
            LLM-generated explanation
        """
        # Extract code snippet
        code_snippet = ""
        if code_unit:
            lines = code_unit.content.split("\n")
            start = max(0, finding.start_line - code_unit.start_line - 3)
            end = min(len(lines), finding.start_line - code_unit.start_line + 5)
            code_snippet = "\n".join(lines[start:end])
        
        # Build prompt
        prompt = build_vulnerability_explanation_prompt(
            finding_type=finding.type,
            file_path=finding.file_path,
            line_number=finding.start_line,
            code_snippet=code_snippet,
            cwe=finding.cwe,
            evidence=finding.evidence,
            language="zh",
        )
        
        # Call LLM
        response = self._llm_client.generate(prompt)
        
        if response.success:
            return response.content
        else:
            # Fallback if LLM fails
            return self._generate_fallback_explanation(finding)
    
    def _generate_fallback_explanation(self, finding: RawFinding) -> str:
        """
        Generate a simple rule-based explanation for a finding.
        
        Used when no LLM client is available or LLM fails.
        
        Args:
            finding: The finding to explain
            
        Returns:
            Human-readable explanation
        """
        # CWE-based explanations
        cwe_explanations = {
            "CWE-89": (
                f"SQL Injection detected at {finding.file_path}:{finding.start_line}. "
                f"User input is directly concatenated into SQL queries, allowing "
                f"attackers to manipulate query logic and potentially access or modify data."
            ),
            "CWE-78": (
                f"Command Injection detected at {finding.file_path}:{finding.start_line}. "
                f"User input is passed to system command execution, allowing "
                f"attackers to run arbitrary commands on the server."
            ),
            "CWE-22": (
                f"Path Traversal detected at {finding.file_path}:{finding.start_line}. "
                f"User input is used in file path operations without validation, "
                f"allowing attackers to access files outside intended directories."
            ),
            "CWE-79": (
                f"Cross-Site Scripting (XSS) detected at {finding.file_path}:{finding.start_line}. "
                f"User input is rendered in HTML without sanitization, allowing "
                f"attackers to inject malicious scripts."
            ),
            "CWE-502": (
                f"Insecure Deserialization detected at {finding.file_path}:{finding.start_line}. "
                f"Untrusted data is deserialized without validation, potentially "
                f"leading to remote code execution."
            ),
            "CWE-798": (
                f"Hardcoded Secret detected at {finding.file_path}:{finding.start_line}. "
                f"Sensitive credentials are hardcoded in source code, exposing "
                f"them to anyone with access to the code."
            ),
        }
        
        # Check if we have a CWE-specific explanation
        if finding.cwe and finding.cwe in cwe_explanations:
            return cwe_explanations[finding.cwe]
        
        # Generic explanation
        return (
            f"The analyzer reported a possible {finding.type} at "
            f"{finding.file_path}:{finding.start_line}. "
            f"This may allow attacker-controlled input to affect system behavior."
        )
    
    def set_llm_client(self, client: LLMClientBase) -> None:
        """
        Set or update the LLM client.
        
        Args:
            client: New LLM client to use
        """
        self._llm_client = client
    
    def get_llm_client(self) -> LLMClientBase | None:
        """
        Get the current LLM client.
        
        Returns:
            Current LLM client or None
        """
        return self._llm_client