"""
Scan session API routes.

Provides endpoints to query specific scan results by scan_id.
These routes complement the legacy /findings, /evidence, /agents/logs,
and /report/* routes by allowing retrieval of historical scan results.

Routes:
- GET /scans/{scan_id}/findings
- GET /scans/{scan_id}/findings/view  (UI-friendly view model)
- GET /scans/{scan_id}/evidence
- GET /scans/{scan_id}/agents/logs
- GET /scans/{scan_id}/metadata
- GET /scans/{scan_id}/analyzer-info
- GET /scans/{scan_id}/report/json
- GET /scans/{scan_id}/report/markdown
- GET /scans/{scan_id}/report/html
"""

from fastapi import APIRouter, HTTPException, Response

from api.state import audit_state
from api.view_models import ScanView
from report.json_report import build_json_report
from report.markdown_report import build_markdown_report
from report.html_report import build_html_report

router = APIRouter(tags=["scans"])


def _get_result_or_404(scan_id: str):
    """Get audit result by scan_id or raise 404."""
    result = audit_state.get_by_id(scan_id)
    if result is None:
        raise HTTPException(status_code=404, detail=f"Scan not found: {scan_id}")
    return result


@router.get("/scans/{scan_id}/findings")
async def get_scan_findings(scan_id: str):
    """
    Return findings from a specific scan session.

    Args:
        scan_id: The scan session identifier returned by POST /scan.

    Returns:
        List of findings for the specified scan.

    Raises:
        404: If scan_id does not exist.
    """
    result = _get_result_or_404(scan_id)
    return [f.model_dump(mode="json") for f in result.findings]


@router.get("/scans/{scan_id}/evidence")
async def get_scan_evidence(scan_id: str):
    """
    Return evidence bundles from a specific scan session.

    Args:
        scan_id: The scan session identifier returned by POST /scan.

    Returns:
        List of evidence bundles for the specified scan.

    Raises:
        404: If scan_id does not exist.
    """
    result = _get_result_or_404(scan_id)
    return [e.model_dump(mode="json") for e in result.evidence]


@router.get("/scans/{scan_id}/agents/logs")
async def get_scan_agent_logs(scan_id: str):
    """
    Return agent execution logs from a specific scan session.

    Args:
        scan_id: The scan session identifier returned by POST /scan.

    Returns:
        List of agent logs for the specified scan.

    Raises:
        404: If scan_id does not exist.
    """
    result = _get_result_or_404(scan_id)
    return [l.model_dump(mode="json") for l in result.agent_logs]


@router.get("/scans/{scan_id}/report/json")
async def get_scan_report_json(scan_id: str):
    """
    Return the full audit result from a specific scan as JSON.

    Args:
        scan_id: The scan session identifier returned by POST /scan.

    Returns:
        Full audit result in JSON format.

    Raises:
        404: If scan_id does not exist.
    """
    result = _get_result_or_404(scan_id)
    return build_json_report(result)


@router.get("/scans/{scan_id}/report/markdown")
async def get_scan_report_markdown(scan_id: str):
    """
    Return the audit report from a specific scan as Markdown.

    Args:
        scan_id: The scan session identifier returned by POST /scan.

    Returns:
        Audit report in Markdown format.

    Raises:
        404: If scan_id does not exist.
    """
    result = _get_result_or_404(scan_id)
    markdown_content = build_markdown_report(result)
    return Response(content=markdown_content, media_type="text/markdown")


@router.get("/scans/{scan_id}/report/html")
async def get_scan_report_html(scan_id: str):
    """
    Return the audit report from a specific scan as HTML.

    Args:
        scan_id: The scan session identifier returned by POST /scan.

    Returns:
        Audit report in HTML format.

    Raises:
        404: If scan_id does not exist.
    """
    result = _get_result_or_404(scan_id)
    html_content = build_html_report(result)
    return Response(content=html_content, media_type="text/html")


@router.get("/scans/{scan_id}/metadata")
async def get_scan_metadata(scan_id: str):
    """
    Return the metadata dict from a specific scan session.

    Metadata typically contains analyzer execution information
    (analyzer_runs, analyzer_errors, skipped_languages) and
    any other diagnostic data produced during the audit pipeline.

    Args:
        scan_id: The scan session identifier returned by POST /scan.

    Returns:
        Dict with scan metadata. Returns an empty dict if no metadata exists.

    Raises:
        404: If scan_id does not exist.
    """
    result = _get_result_or_404(scan_id)
    return result.metadata or {}


@router.get("/scans/{scan_id}/analyzer-info")
async def get_scan_analyzer_info(scan_id: str):
    """
    Return analyzer execution details from a specific scan session.

    Returns structured information about which analyzers ran, which
    failed, and which languages were skipped during the scan.

    Args:
        scan_id: The scan session identifier returned by POST /scan.

    Returns:
        Dict with keys:
        - analyzer_runs: List of analyzer execution records
        - analyzer_errors: List of analyzer error records
        - skipped_languages: List of skipped language records

    Raises:
        404: If scan_id does not exist.
    """
    result = _get_result_or_404(scan_id)
    return (result.metadata or {}).get("analyzer_info", {
        "analyzer_runs": [],
        "analyzer_errors": [],
        "skipped_languages": [],
    })


@router.get("/scans/{scan_id}/findings/view")
async def get_scan_findings_view(scan_id: str):
    """
    Return UI-friendly finding views from a specific scan session.

    This endpoint returns FindingView objects that merge data from
    RawFinding and JudgeDecision, providing a stable contract for
    UI rendering. The UI should prefer this endpoint over the raw
    /findings endpoint.

    Field Mapping:
    - file_path -> file
    - start_line -> line
    - JudgeDecision.risk_score -> risk_score
    - JudgeDecision.verdict -> verdict

    Args:
        scan_id: The scan session identifier returned by POST /scan.

    Returns:
        ScanView with findings as FindingView objects:
        - scan_id: Scan identifier
        - status: "completed"
        - total_findings: Count of findings
        - confirmed_count: Confirmed findings
        - suspicious_count: Suspicious findings
        - rejected_count: Rejected findings
        - risk_score: Average risk score
        - languages: Languages scanned
        - findings: List of FindingView objects

    Raises:
        404: If scan_id does not exist.
    """
    result = _get_result_or_404(scan_id)
    view = ScanView.from_audit_result(scan_id, result)
    return view.to_dict()
