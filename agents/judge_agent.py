"""
Judge agent for making final vulnerability decisions.

The JudgeAgent evaluates findings and hypotheses to make
final determinations about the validity of vulnerabilities.
"""

from audit_core.models import RawFinding, AgentHypothesis, EvidenceBundle, JudgeDecision, AgentLog
from agents.base_agent import BaseAgent


class JudgeAgent(BaseAgent):
    """
    Agent that makes final decisions on vulnerability validity.
    
    Uses simple rules to determine verdict:
    - confidence == high and severity in ERROR/HIGH/CRITICAL -> confirmed
    - confidence == medium -> suspicious
    - confidence == low -> suspicious
    - insufficient evidence -> suspicious
    """
    
    name = "judge"
    
    def run(
        self,
        finding: RawFinding,
        hypotheses: list[AgentHypothesis],
        evidence_bundle: EvidenceBundle | None = None
    ) -> tuple[JudgeDecision, AgentLog]:
        """
        Make a decision on a finding.
        
        Args:
            finding: The finding to evaluate
            hypotheses: List of agent hypotheses
            evidence_bundle: Optional evidence bundle
            
        Returns:
            Tuple of (decision, log)
        """
        # Determine verdict based on confidence and severity
        verdict = self._determine_verdict(finding)
        
        # Calculate risk score
        risk_score = self._calculate_risk_score(finding, verdict)
        
        decision = JudgeDecision(
            finding_id=finding.id,
            verdict=verdict,
            confidence=finding.confidence,
            risk_score=risk_score,
            reason=self._generate_reason(finding, verdict)
        )
        
        log = AgentLog(
            agent_name=self.name,
            stage="judge",
            message=f"JudgeAgent evaluated finding {finding.id}: verdict={verdict}, risk={risk_score}",
            input_refs=[finding.id] + [h.id for h in hypotheses],
            output_refs=[decision.id]
        )
        
        return decision, log
    
    def _determine_verdict(self, finding: RawFinding) -> str:
        """
        Determine verdict based on confidence and severity.
        
        Args:
            finding: The finding to evaluate
            
        Returns:
            Verdict: confirmed, suspicious, or rejected
        """
        confidence = finding.confidence.lower()
        severity = finding.severity.upper()
        
        high_severities = {"ERROR", "HIGH", "CRITICAL"}
        
        if confidence == "high" and severity in high_severities:
            return "confirmed"
        elif confidence == "low":
            return "suspicious"
        else:
            return "suspicious"
    
    def _calculate_risk_score(self, finding: RawFinding, verdict: str) -> float:
        """
        Calculate risk score for a finding.
        
        Args:
            finding: The finding to score
            verdict: The determined verdict
            
        Returns:
            Risk score between 0 and 100
        """
        # Base score from severity
        severity_scores = {
            "CRITICAL": 90,
            "ERROR": 80,
            "HIGH": 80,
            "WARN": 50,
            "MEDIUM": 50,
            "INFO": 20,
            "LOW": 20,
            "UNKNOWN": 10
        }
        base_score = severity_scores.get(finding.severity.upper(), 10)
        
        # Adjust based on confidence
        confidence_multipliers = {
            "high": 1.0,
            "medium": 0.7,
            "low": 0.4
        }
        multiplier = confidence_multipliers.get(finding.confidence.lower(), 0.5)
        
        # Adjust based on verdict
        verdict_multipliers = {
            "confirmed": 1.0,
            "suspicious": 0.6,
            "rejected": 0.1
        }
        verdict_mult = verdict_multipliers.get(verdict.lower(), 0.5)
        
        return min(100, base_score * multiplier * verdict_mult)
    
    def _generate_reason(self, finding: RawFinding, verdict: str) -> str:
        """
        Generate reason for the decision.
        
        Args:
            finding: The finding
            verdict: The verdict
            
        Returns:
            Human-readable reason
        """
        return (
            f"Finding has {finding.confidence} confidence and {finding.severity} severity. "
            f"Verdict: {verdict}."
        )
