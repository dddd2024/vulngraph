"""
Findings API routes.

GET /findings — return findings from the most recent scan.
"""

from fastapi import APIRouter

from api.state import audit_state

router = APIRouter(tags=["findings"])


@router.get("/findings")
async def list_findings():
    """Return all findings from the most recent scan."""
    result = audit_state.get()
    return [f.model_dump(mode="json") for f in result.findings]
