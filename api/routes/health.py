"""
Health check API routes.

Simple health check endpoint.
"""

from fastapi import APIRouter
from api.schemas import HealthResponse

router = APIRouter(tags=["health"])


@router.get("/health", response_model=HealthResponse)
async def health_check():
    """
    Health check endpoint.
    
    Returns the service status.
    """
    return HealthResponse(status="ok")
