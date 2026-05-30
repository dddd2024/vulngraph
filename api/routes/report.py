"""
Report API routes.

GET /report/json — return the full audit result as JSON.
"""

from fastapi import APIRouter

from api.state import audit_state

router = APIRouter(tags=["report"])


@router.get("/report/json")
async def report_json():
    """Return the full audit result from the most recent scan."""
    result = audit_state.get()
    return result.model_dump(mode="json")
