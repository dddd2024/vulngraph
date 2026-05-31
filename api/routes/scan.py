"""
Scan API routes.

POST /scan is the primary entry point for the new audit pipeline.
It delegates to AuditOrchestrator, stores the result with a scan_id,
and returns both the scan_id and full audit result.
"""

from fastapi import APIRouter, HTTPException
from api.schemas import ScanRequest, ScanResponse
from api.state import audit_state
from audit_core.orchestrator import AuditOrchestrator

router = APIRouter(tags=["scan"])

# Shared orchestrator instance
orchestrator = AuditOrchestrator()


def _run_scan(request: ScanRequest) -> tuple[str, dict]:
    """
    Execute scan via AuditOrchestrator, persist with scan_id, and return result.

    Returns:
        Tuple of (scan_id, response_dict)
    """
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

    # Create session and get scan_id
    scan_id = audit_state.create_session(result)

    response_data = {
        "scan_id": scan_id,
        "summary": result.summary.model_dump(mode="json"),
        "findings": [f.model_dump(mode="json") for f in result.findings],
        "evidence": [e.model_dump(mode="json") for e in result.evidence],
        "agent_logs": [l.model_dump(mode="json") for l in result.agent_logs],
    }

    return scan_id, response_data


@router.post("/scan", response_model=ScanResponse)
async def scan(request: ScanRequest) -> ScanResponse:
    """
    Primary scan endpoint.

    Accepts code snippets, local repo paths, or GitHub URLs and
    returns a full audit result including:
    - scan_id: unique identifier for this scan session
    - summary: audit summary statistics
    - findings: list of detected vulnerabilities
    - evidence: evidence bundles for findings
    - agent_logs: agent execution logs

    Use the returned scan_id to query specific scan results via
    /scans/{scan_id}/findings, /scans/{scan_id}/evidence, etc.
    """
    try:
        _, response_data = _run_scan(request)
        return ScanResponse(**response_data)
    except HTTPException:
        raise
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Scan failed: {str(e)}")
