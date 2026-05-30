"""
Base agent interface for all LLM agents.

Agents perform reasoning and analysis tasks using LLMs.
They do NOT directly read files or scan repositories - they only process
structured objects: CodeUnit, RawFinding, EvidenceBundle.
"""

from abc import ABC, abstractmethod


class BaseAgent(ABC):
    """
    Abstract base class for all agents.
    
    Agents use LLMs to perform reasoning tasks on structured data.
    They do NOT:
    - Read files directly
    - Scan repositories directly
    
    They ONLY process:
    - CodeUnit objects
    - RawFinding objects
    - EvidenceBundle objects
    
    Attributes:
        name: Unique name of the agent
    """
    
    name: str = "base"
    
    @abstractmethod
    def run(self, *args, **kwargs):
        """
        Execute the agent's main task.
        
        Args:
            *args: Variable positional arguments
            **kwargs: Variable keyword arguments
            
        Returns:
            Agent-specific output
        """
        pass
