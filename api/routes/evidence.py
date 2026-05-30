"""
Evidence API routes.

GET /evidence — return evidence bundles from the most recent scan.
"""

from fastapi import APIRouter

from api.state import audit_state

router = APIRouter(tags=["evidence"])


@router.get("/evidence")
async def list_evidence():
    """Return all evidence bundles from the most recent scan."""
    result = audit_state.get()
    return [e.model_dump(mode="json") for e in result.evidence]
