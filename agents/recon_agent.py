"""
Reconnaissance agent for initial code inspection.

The ReconAgent performs initial analysis of code units to identify
potential areas of interest for further analysis.
"""

from audit_core.models import CodeUnit, AgentHypothesis, AgentLog
from agents.base_agent import BaseAgent


class ReconAgent(BaseAgent):
    """
    Agent that performs initial reconnaissance on code.
    
    Currently returns empty hypotheses and only logs inspection activity.
    Full reconnaissance logic will be implemented in a future stage.
    """
    
    name = "recon"
    
    def run(self, code_units: list[CodeUnit]) -> tuple[list[AgentHypothesis], list[AgentLog]]:
        """
        Run reconnaissance on code units.
        
        Args:
            code_units: List of code units to inspect
            
        Returns:
            Tuple of (hypotheses, logs)
            - hypotheses: Currently empty list (placeholder)
            - logs: List of AgentLog entries
        """
        hypotheses = []
        logs = []
        
        # Log inspection activity
        log = AgentLog(
            agent_name=self.name,
            stage="recon",
            message=f"ReconAgent inspected {len(code_units)} code units.",
            input_refs=[unit.id for unit in code_units],
            output_refs=[]
        )
        logs.append(log)
        
        # TODO: Implement actual reconnaissance logic
        # For now, just return empty hypotheses
        
        return hypotheses, logs
