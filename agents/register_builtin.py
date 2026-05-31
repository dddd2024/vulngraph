"""
Built-in agent registration entry point (aggregator).

This module aggregates all agent subdirectory registrations into a single
entry point. Each agent type has its own register.py in its subdirectory,
and this module simply calls each subdirectory's register_agents() function.

To add a new agent:
1. Create a subdirectory under agents/ (e.g., agents/my_agent/)
2. Create register.py with a register_agents(registry) function
3. Import and call it in this file's register_builtin_agents()

This design reduces merge conflicts when multiple team members add agents
in parallel — each member only modifies their own subdirectory.

Team Member Assignment: All members can add agents independently
"""

from __future__ import annotations

from agents.registry import AgentRegistry


def register_builtin_agents(registry: AgentRegistry) -> None:
    """
    Register all built-in agents into the given registry.

    This function aggregates registrations from each agent subdirectory.
    Each subdirectory provides its own register_agents() function.

    Currently registered agents:
    - recon: agents/recon/register.py -> ReconAgent
    - analysis: agents/analysis/register.py -> AnalysisAgent
    - judge: agents/judge/register.py -> JudgeAgent

    Args:
        registry: The AgentRegistry instance to populate.
    """
    # Import and call each subdirectory's registration function
    # Each import is in a separate try block to allow partial loading

    try:
        from agents.recon.register import register_agents as register_recon
        register_recon(registry)
    except ImportError:
        pass  # ReconAgent not available

    try:
        from agents.analysis.register import register_agents as register_analysis
        register_analysis(registry)
    except ImportError:
        pass  # AnalysisAgent not available

    try:
        from agents.judge.register import register_agents as register_judge
        register_judge(registry)
    except ImportError:
        pass  # JudgeAgent not available

    # Add new agent registrations here:
    # try:
    #     from agents.my_agent.register import register_agents as register_my_agent
    #     register_my_agent(registry)
    # except ImportError:
    #     pass