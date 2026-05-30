"""
Agent logs API routes.

GET /agents/logs — return agent execution logs from the most recent scan.
"""

from fastapi import APIRouter

from api.state import audit_state

router = APIRouter(tags=["agents"])


@router.get("/agents/logs")
async def list_agent_logs():
    """Return all agent logs from the most recent scan."""
    result = audit_state.get()
    return [l.model_dump(mode="json") for l in result.agent_logs]
