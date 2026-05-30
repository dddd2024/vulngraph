"""
Scan API routes.

New scan endpoint using AuditOrchestrator.
"""

from fastapi import APIRouter, HTTPException
from api.schemas import ScanRequest, ScanResponse
from audit_core.orchestrator import AuditOrchestrator

router = APIRouter(prefix="/scan", tags=["scan"])

# Initialize orchestrator
orchestrator = AuditOrchestrator()


@router.post("/new", response_model=ScanResponse)
async def scan_new(request: ScanRequest):
    """
    New scan endpoint using AuditOrchestrator.
    
    This is the primary scan endpoint for the new audit pipeline.
    """
    try:
        # Validate input
        if request.input_type not in ["code", "path", "github"]:
            raise HTTPException(
                status_code=400,
                detail=f"Invalid input_type: {request.input_type}. Must be 'code', 'path', or 'github'"
            )
        
        # Run scan
        result = orchestrator.scan(
            input_type=request.input_type,
            code=request.code,
            repo_path=request.repo_path,
            repo_url=request.repo_url,
            language=request.language if request.language != "auto" else None
        )
        
        # Convert to response
        return ScanResponse(
            summary=result.summary.model_dump(mode="json"),
            findings=[f.model_dump(mode="json") for f in result.findings],
            evidence=[e.model_dump(mode="json") for e in result.evidence],
            agent_logs=[l.model_dump(mode="json") for l in result.agent_logs]
        )
    
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Scan failed: {str(e)}")
