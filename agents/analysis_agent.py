"""
Analysis agent for generating vulnerability hypotheses.

The AnalysisAgent analyzes findings and generates hypotheses about
potential vulnerabilities without calling real LLMs in Stage 1.
"""

from audit_core.models import CodeUnit, RawFinding, AgentHypothesis, AgentLog
from agents.base_agent import BaseAgent


class AnalysisAgent(BaseAgent):
    """
    Agent that analyzes findings and generates hypotheses.
    
    Currently generates simple explanations based on finding data
    without calling real LLMs. Full LLM integration will be added later.
    """
    
    name = "analysis"
    
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
        # Generate simple explanation based on finding data
        explanation = self._generate_explanation(finding)
        
        hypothesis = AgentHypothesis(
            agent_name=self.name,
            finding_id=finding.id,
            hypothesis=f"Potential {finding.type} vulnerability detected.",
            vulnerability_type=finding.type,
            reasoning_summary=explanation,
            confidence=finding.confidence,
            supporting_evidence_ids=[finding.id]
        )
        
        log = AgentLog(
            agent_name=self.name,
            stage="analysis",
            message=f"AnalysisAgent analyzed finding {finding.id} of type {finding.type}.",
            input_refs=[finding.id, code_unit.id if code_unit else None],
            output_refs=[hypothesis.id]
        )
        
        return hypothesis, log
    
    def _generate_explanation(self, finding: RawFinding) -> str:
        """
        Generate a simple explanation for a finding.
        
        Args:
            finding: The finding to explain
            
        Returns:
            Human-readable explanation
        """
        return (
            f"The analyzer reported a possible {finding.type} at "
            f"{finding.file_path}:{finding.start_line}. "
            f"This may allow attacker-controlled input to affect system behavior."
        )
