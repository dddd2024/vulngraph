"""
Judge agent for final vulnerability verdict.

The JudgeAgent evaluates findings and hypotheses to make final determinations
about vulnerability validity, assigning verdicts and risk scores.
"""

from audit_core.models import (
    RawFinding,
    AgentHypothesis,
    AgentLog,
    JudgeDecision,
    EvidenceBundle,
)
from agents.interfaces import JudgeAgentBase


class JudgeAgent(JudgeAgentBase):
    """
    Agent that makes final decisions on vulnerability findings.

    Evaluates findings, hypotheses, and evidence to assign verdicts:
    - confirmed: High confidence vulnerability
    - suspicious: Potential vulnerability requiring review
    - rejected: Not a vulnerability or false positive

    Input:
        finding: RawFinding to evaluate
        hypotheses: List of AgentHypothesis from other agents
        evidence_bundle: Optional EvidenceBundle with supporting evidence

    Output:
        Tuple of (JudgeDecision, AgentLog)

    Does NOT read files directly - only uses provided structured data.
    """

    name = "judge"

    # Confidence scores for verdict calculation
    CONFIDENCE_SCORES = {
        "high": 0.9,
        "medium": 0.6,
        "low": 0.3,
    }

    # Severity scores for risk calculation
    SEVERITY_SCORES = {
        "ERROR": 90,
        "WARN": 60,
        "INFO": 30,
    }

    # Verdict thresholds
    CONFIRMED_THRESHOLD = 70
    REJECTED_THRESHOLD = 30

    def run(
        self,
        finding: RawFinding,
        hypotheses: list[AgentHypothesis],
        evidence_bundle: EvidenceBundle | None = None,
    ) -> tuple[JudgeDecision, AgentLog]:
        """
        Make a decision on a finding.

        Args:
            finding: The RawFinding to evaluate
            hypotheses: List of AgentHypothesis from other agents
            evidence_bundle: Optional EvidenceBundle with evidence

        Returns:
            Tuple of (JudgeDecision, AgentLog)
        """
        # Calculate base scores
        confidence_score = self._calculate_confidence_score(finding, hypotheses)
        severity_score = self._calculate_severity_score(finding)
        evidence_score = self._calculate_evidence_score(evidence_bundle)

        # Calculate final risk score (0-100)
        risk_score = self._calculate_risk_score(
            confidence_score, severity_score, evidence_score
        )

        # Determine verdict
        verdict = self._determine_verdict(risk_score, finding, hypotheses)

        # Determine confidence level
        confidence = self._determine_confidence(confidence_score)

        # Generate reason
        reason = self._generate_reason(
            finding, hypotheses, verdict, risk_score, evidence_bundle
        )

        # Create decision
        decision = JudgeDecision(
            finding_id=finding.id,
            verdict=verdict,
            confidence=confidence,
            risk_score=risk_score,
            reason=reason,
            metadata={
                "finding_type": finding.type,
                "finding_severity": finding.severity,
                "finding_confidence": finding.confidence,
                "num_hypotheses": len(hypotheses),
                "has_evidence": evidence_bundle is not None,
                "confidence_score": confidence_score,
                "severity_score": severity_score,
                "evidence_score": evidence_score,
            }
        )

        # Create log
        log = AgentLog(
            agent_name=self.name,
            stage="judge",
            message=f"Judged {finding.type} finding: {verdict} (risk: {risk_score})",
            input_refs=[finding.id] + [h.id for h in hypotheses],
            output_refs=[decision.id],
            metadata={
                "verdict": verdict,
                "risk_score": risk_score,
                "num_hypotheses_considered": len(hypotheses),
            }
        )

        return decision, log

    def _calculate_confidence_score(
        self,
        finding: RawFinding,
        hypotheses: list[AgentHypothesis],
    ) -> float:
        """
        Calculate confidence score based on finding and hypotheses.

        Args:
            finding: The RawFinding
            hypotheses: List of AgentHypothesis

        Returns:
            Confidence score (0.0 - 1.0)
        """
        # Base confidence from finding
        base_confidence = self.CONFIDENCE_SCORES.get(finding.confidence, 0.3)

        # Adjust based on hypotheses
        if not hypotheses:
            # No hypotheses - reduce confidence
            return base_confidence * 0.7

        # Average hypothesis confidence
        hypo_confidences = [
            self.CONFIDENCE_SCORES.get(h.confidence, 0.3)
            for h in hypotheses
        ]
        avg_hypo_confidence = sum(hypo_confidences) / len(hypo_confidences)

        # Weight finding confidence more heavily
        return (base_confidence * 0.6) + (avg_hypo_confidence * 0.4)

    def _calculate_severity_score(self, finding: RawFinding) -> float:
        """
        Calculate severity score from finding.

        Args:
            finding: The RawFinding

        Returns:
            Severity score (0 - 100)
        """
        return self.SEVERITY_SCORES.get(finding.severity, 30)

    def _calculate_evidence_score(
        self,
        evidence_bundle: EvidenceBundle | None,
    ) -> float:
        """
        Calculate evidence score from evidence bundle.

        Args:
            evidence_bundle: Optional EvidenceBundle

        Returns:
            Evidence score (0 - 100)
        """
        if evidence_bundle is None:
            return 0

        score = 0

        # Points for code snippets
        if evidence_bundle.snippets:
            score += min(len(evidence_bundle.snippets) * 10, 30)

        # Points for call chain
        if evidence_bundle.call_chain:
            score += min(len(evidence_bundle.call_chain) * 5, 20)

        # Points for agent hypotheses
        if evidence_bundle.agent_hypotheses:
            score += min(len(evidence_bundle.agent_hypotheses) * 10, 30)

        # Points for agent logs
        if evidence_bundle.agent_logs:
            score += min(len(evidence_bundle.agent_logs) * 2, 10)

        return min(score, 100)

    def _calculate_risk_score(
        self,
        confidence_score: float,
        severity_score: float,
        evidence_score: float,
    ) -> int:
        """
        Calculate final risk score.

        Args:
            confidence_score: Confidence score (0.0 - 1.0)
            severity_score: Severity score (0 - 100)
            evidence_score: Evidence score (0 - 100)

        Returns:
            Risk score (0 - 100)
        """
        # Weighted combination
        # Severity is most important, then confidence, then evidence
        risk = (
            severity_score * 0.5 +
            (confidence_score * 100) * 0.3 +
            evidence_score * 0.2
        )
        return int(risk)

    def _determine_verdict(
        self,
        risk_score: int,
        finding: RawFinding,
        hypotheses: list[AgentHypothesis],
    ) -> str:
        """
        Determine verdict based on risk score and context.

        Args:
            risk_score: Calculated risk score
            finding: The RawFinding
            hypotheses: List of AgentHypothesis

        Returns:
            Verdict string: "confirmed", "suspicious", or "rejected"
        """
        # High risk with supporting hypotheses = confirmed
        if risk_score >= self.CONFIRMED_THRESHOLD and hypotheses:
            return "confirmed"

        # Medium risk or high risk without hypotheses = suspicious
        if risk_score >= self.REJECTED_THRESHOLD:
            return "suspicious"

        # Low risk = rejected
        return "rejected"

    def _determine_confidence(self, confidence_score: float) -> str:
        """
        Determine confidence level from score.

        Args:
            confidence_score: Calculated confidence score (0.0 - 1.0)

        Returns:
            Confidence string: "high", "medium", or "low"
        """
        if confidence_score >= 0.7:
            return "high"
        elif confidence_score >= 0.4:
            return "medium"
        else:
            return "low"

    def _generate_reason(
        self,
        finding: RawFinding,
        hypotheses: list[AgentHypothesis],
        verdict: str,
        risk_score: int,
        evidence_bundle: EvidenceBundle | None,
    ) -> str:
        """
        Generate reason for the decision.

        Args:
            finding: The RawFinding
            hypotheses: List of AgentHypothesis
            verdict: The verdict
            risk_score: The risk score
            evidence_bundle: Optional EvidenceBundle

        Returns:
            Reason string
        """
        parts = []

        # Base reason from finding
        parts.append(f"Finding: {finding.message}")
        parts.append(f"Severity: {finding.severity}, Confidence: {finding.confidence}")

        # Hypotheses contribution
        if hypotheses:
            parts.append(f"Considered {len(hypotheses)} agent hypotheses.")
            high_conf_hypotheses = [h for h in hypotheses if h.confidence == "high"]
            if high_conf_hypotheses:
                parts.append(f"{len(high_conf_hypotheses)} high-confidence hypotheses support this finding.")
        else:
            parts.append("No agent hypotheses available for this finding.")

        # Evidence contribution
        if evidence_bundle:
            evidence_parts = []
            if evidence_bundle.snippets:
                evidence_parts.append(f"{len(evidence_bundle.snippets)} code snippets")
            if evidence_bundle.call_chain:
                evidence_parts.append(f"call chain of {len(evidence_bundle.call_chain)} nodes")
            if evidence_parts:
                parts.append(f"Evidence includes: {', '.join(evidence_parts)}.")

        # Verdict explanation
        if verdict == "confirmed":
            parts.append(f"Verdict: CONFIRMED (risk score: {risk_score}). "
                        "This appears to be a genuine vulnerability requiring remediation.")
        elif verdict == "suspicious":
            parts.append(f"Verdict: SUSPICIOUS (risk score: {risk_score}). "
                        "This finding requires manual review to confirm.")
        else:
            parts.append(f"Verdict: REJECTED (risk score: {risk_score}). "
                        "This appears to be a false positive or low-risk issue.")

        return " ".join(parts)
