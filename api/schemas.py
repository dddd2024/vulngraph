"""
API request/response schemas.

Defines Pydantic models for API requests and responses.
"""

from pydantic import BaseModel
from typing import Optional


class ScanRequest(BaseModel):
    """Request model for /scan endpoint."""
    input_type: str  # 'code', 'path', 'github'
    code: Optional[str] = None
    repo_path: Optional[str] = None
    repo_url: Optional[str] = None
    language: str = "auto"


class ScanResponse(BaseModel):
    """Response model for /scan endpoint."""
    summary: dict
    findings: list[dict]
    evidence: list[dict]
    agent_logs: list[dict]


class HealthResponse(BaseModel):
    """Response model for /health endpoint."""
    status: str
