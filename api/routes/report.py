"""
Report API routes.

GET /report/json — return the full audit result as JSON.
GET /report/markdown — return the audit report as Markdown.
GET /report/html — return the audit report as HTML.
"""

from fastapi import APIRouter, Response

from api.state import audit_state
from report.json_report import build_json_report
from report.markdown_report import build_markdown_report
from report.html_report import build_html_report

router = APIRouter(tags=["report"])


@router.get("/report/json")
async def report_json():
    """Return the full audit result from the most recent scan as JSON."""
    result = audit_state.get()
    return build_json_report(result)


@router.get("/report/markdown")
async def report_markdown():
    """Return the audit report from the most recent scan as Markdown."""
    result = audit_state.get()
    markdown_content = build_markdown_report(result)
    return Response(content=markdown_content, media_type="text/markdown")


@router.get("/report/html")
async def report_html():
    """Return the audit report from the most recent scan as HTML."""
    result = audit_state.get()
    html_content = build_html_report(result)
    return Response(content=html_content, media_type="text/html")
