"""
Scan API routes.

POST /scan is the primary entry point for the new audit pipeline.
It delegates to AuditOrchestrator and stores the result in api.state.
"""

from fastapi import APIRouter, HTTPException
from api.schemas import ScanRequest, ScanResponse
from api.state import audit_state
from audit_core.orchestrator import AuditOrchestrator

router = APIRouter(tags=["scan"])

# Shared orchestrator instance
orchestrator = AuditOrchestrator()


def _run_scan(request: ScanRequest) -> dict:
    """Execute scan via AuditOrchestrator and persist the result."""
    if request.input_type not in ("code", "path", "github"):
        raise HTTPException(
            status_code=400,
            detail=f"Invalid input_type: {request.input_type}. Must be 'code', 'path', or 'github'",
        )

    result = orchestrator.scan(
        input_type=request.input_type,
        code=request.code,
        repo_path=request.repo_path,
        repo_url=request.repo_url,
        language=request.language if request.language != "auto" else None,
    )

    # Persist so that sub-resource routes can read it
    audit_state.set(result)

    return {
        "summary": result.summary.model_dump(mode="json"),
        "findings": [f.model_dump(mode="json") for f in result.findings],
        "evidence": [e.model_dump(mode="json") for e in result.evidence],
        "agent_logs": [l.model_dump(mode="json") for l in result.agent_logs],
    }


@router.post("/scan", response_model=ScanResponse)
async def scan(request: ScanRequest) -> ScanResponse:
    """
    Primary scan endpoint.

    Accepts code snippets, local repo paths, or GitHub URLs and
    returns a full audit result including summary, findings, evidence
    bundles, and agent logs.
    """
    try:
        return ScanResponse(**_run_scan(request))
    except HTTPException:
        raise
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Scan failed: {str(e)}")
