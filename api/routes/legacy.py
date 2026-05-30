"""
Legacy API routes for backward compatibility.

Wraps new AuditOrchestrator to maintain compatibility with old API.
"""

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import Optional
from audit_core.orchestrator import AuditOrchestrator

router = APIRouter(tags=["legacy"])

# Initialize orchestrator
orchestrator = AuditOrchestrator()


class LegacyScanRequest(BaseModel):
    """Legacy scan request model."""
    input_type: str
    code: Optional[str] = None
    repo_path: Optional[str] = None
    repo_url: Optional[str] = None
    language: str = "auto"


@router.post("/scan")
async def legacy_scan(request: LegacyScanRequest):
    """
    Legacy scan endpoint.
    
    Wraps new AuditOrchestrator but returns legacy format.
    Maintains backward compatibility with old API clients.
    """
    try:
        # Run scan using new orchestrator
        result = orchestrator.scan(
            input_type=request.input_type,
            code=request.code,
            repo_path=request.repo_path,
            repo_url=request.repo_url,
            language=request.language if request.language != "auto" else None
        )
        
        # Transform to legacy format
        legacy_findings = []
        for finding in result.findings:
            legacy_findings.append({
                "rule_id": finding.rule_id,
                "type": finding.type,
                "severity": finding.severity,
                "confidence": finding.confidence,
                "file_path": finding.file_path,
                "start_line": finding.start_line,
                "message": finding.message,
                "engine": finding.engine
            })
        
        return {
            "status": "success",
            "findings": legacy_findings,
            "summary": {
                "total_findings": result.summary.total_findings,
                "total_files": result.summary.total_code_units,
                "languages": result.summary.languages
            }
        }
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
