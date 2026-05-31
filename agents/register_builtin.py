"""
Built-in agent registration entry point.

Registers the three core agents (Recon, Analysis, Judge) into the
provided ``AgentRegistry``.  To add a new built-in agent, add the
registration call here — no changes to ``agents/registry.py`` or
``audit_core/orchestrator.py`` are required.
"""

from __future__ import annotations

from agents.registry import AgentRegistry


def register_builtin_agents(registry: AgentRegistry) -> None:
    """
    Register all built-in agents into the given registry.

    Currently registers:
    - ``recon``  – :class:`~agents.recon_agent.ReconAgent`
    - ``analysis`` – :class:`~agents.analysis_agent.AnalysisAgent`
    - ``judge``  – :class:`~agents.judge_agent.JudgeAgent`

    Args:
        registry: The ``AgentRegistry`` instance to populate.
    """
    from agents.recon_agent import ReconAgent
    from agents.analysis_agent import AnalysisAgent
    from agents.judge_agent import JudgeAgent

    registry.register(ReconAgent())
    registry.register(AnalysisAgent())
    registry.register(JudgeAgent())
