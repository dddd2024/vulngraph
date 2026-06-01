"""
扫描会话 API 路由。

提供按 scan_id 查询特定扫描结果的端点：
- GET /scans/{scan_id}/findings — 获取指定扫描的漏洞列表
- GET /scans/{scan_id}/findings/view — 获取 UI 友好的漏洞视图
- GET /scans/{scan_id}/evidence — 获取指定扫描的证据包
- GET /scans/{scan_id}/agents/logs — 获取指定扫描的 Agent 日志
- GET /scans/{scan_id}/metadata — 获取指定扫描的元数据
- GET /scans/{scan_id}/analyzer-info — 获取指定扫描的分析器信息
- GET /scans/{scan_id}/report/json — 获取指定扫描的 JSON 报告
- GET /scans/{scan_id}/report/markdown — 获取指定扫描的 Markdown 报告
- GET /scans/{scan_id}/report/html — 获取指定扫描的 HTML 报告

功能说明:
- 支持查询历史扫描记录
- 提供 UI 友好的视图模型
- 支持多种报告格式导出

异常处理:
- scan_id 不存在时返回 404 错误
- 统一错误响应格式
"""

import time

from fastapi import APIRouter, HTTPException, Response

from api.schemas import ApiResponse
from api.state import audit_state
from api.view_models import ScanView
from report.json_report import build_json_report
from report.markdown_report import build_markdown_report
from report.html_report import build_html_report

router = APIRouter(tags=["scans"])


def _get_result_or_404(scan_id: str):
    """
    根据 scan_id 获取审计结果，不存在则抛出 404 异常。

    Args:
        scan_id: 扫描会话标识符

    Returns:
        AuditResult 对象

    Raises:
        HTTPException: 当 scan_id 不存在时抛出 404 错误
    """
    result = audit_state.get_by_id(scan_id)
    if result is None:
        raise HTTPException(status_code=404, detail=f"Scan not found: {scan_id}")
    return result


@router.get("/scans/{scan_id}/findings", response_model=ApiResponse)
async def get_scan_findings(scan_id: str):
    """
    获取指定扫描会话的漏洞列表。

    请求方式: GET

    入参:
        - scan_id: 扫描会话标识符（路径参数）

    返回内容:
        - code: HTTP状态码
        - message: 响应消息
        - data: 漏洞列表
        - success: 是否成功
        - timestamp: 响应时间戳

    返回示例:
        {
            "code": 200,
            "message": "success",
            "data": [...],
            "success": true,
            "timestamp": 1620000000.0
        }

    异常:
        - 404: scan_id 不存在
        - 500: 获取漏洞列表失败
    """
    try:
        result = _get_result_or_404(scan_id)
        findings_data = [f.model_dump(mode="json") for f in result.findings]

        return ApiResponse(
            code=200,
            message="success",
            data=findings_data,
            success=True,
            timestamp=time.time(),
        )

    except HTTPException as e:
        return ApiResponse(
            code=e.status_code,
            message=e.detail,
            data=None,
            success=False,
            timestamp=time.time(),
        )
    except Exception as e:
        return ApiResponse(
            code=500,
            message=f"获取漏洞列表失败: {str(e)}",
            data=None,
            success=False,
            timestamp=time.time(),
        )


@router.get("/scans/{scan_id}/evidence", response_model=ApiResponse)
async def get_scan_evidence(scan_id: str):
    """
    获取指定扫描会话的证据包列表。

    请求方式: GET

    入参:
        - scan_id: 扫描会话标识符（路径参数）

    返回内容:
        - code: HTTP状态码
        - message: 响应消息
        - data: 证据包列表
        - success: 是否成功
        - timestamp: 响应时间戳

    异常:
        - 404: scan_id 不存在
        - 500: 获取证据包列表失败
    """
    try:
        result = _get_result_or_404(scan_id)
        evidence_data = [e.model_dump(mode="json") for e in result.evidence]

        return ApiResponse(
            code=200,
            message="success",
            data=evidence_data,
            success=True,
            timestamp=time.time(),
        )

    except HTTPException as e:
        return ApiResponse(
            code=e.status_code,
            message=e.detail,
            data=None,
            success=False,
            timestamp=time.time(),
        )
    except Exception as e:
        return ApiResponse(
            code=500,
            message=f"获取证据包列表失败: {str(e)}",
            data=None,
            success=False,
            timestamp=time.time(),
        )


@router.get("/scans/{scan_id}/agents/logs", response_model=ApiResponse)
async def get_scan_agent_logs(scan_id: str):
    """
    获取指定扫描会话的 Agent 执行日志。

    请求方式: GET

    入参:
        - scan_id: 扫描会话标识符（路径参数）

    返回内容:
        - code: HTTP状态码
        - message: 响应消息
        - data: Agent 日志列表
        - success: 是否成功
        - timestamp: 响应时间戳

    异常:
        - 404: scan_id 不存在
        - 500: 获取 Agent 日志失败
    """
    try:
        result = _get_result_or_404(scan_id)
        logs_data = [l.model_dump(mode="json") for l in result.agent_logs]

        return ApiResponse(
            code=200,
            message="success",
            data=logs_data,
            success=True,
            timestamp=time.time(),
        )

    except HTTPException as e:
        return ApiResponse(
            code=e.status_code,
            message=e.detail,
            data=None,
            success=False,
            timestamp=time.time(),
        )
    except Exception as e:
        return ApiResponse(
            code=500,
            message=f"获取 Agent 日志失败: {str(e)}",
            data=None,
            success=False,
            timestamp=time.time(),
        )


@router.get("/scans/{scan_id}/report/json", response_model=ApiResponse)
async def get_scan_report_json(scan_id: str):
    """
    获取指定扫描会话的 JSON 格式审计报告。

    请求方式: GET

    入参:
        - scan_id: 扫描会话标识符（路径参数）

    返回内容:
        - code: HTTP状态码
        - message: 响应消息
        - data: JSON 格式审计报告
        - success: 是否成功
        - timestamp: 响应时间戳

    异常:
        - 404: scan_id 不存在
        - 500: 生成报告失败
    """
    try:
        result = _get_result_or_404(scan_id)
        report_data = build_json_report(result)

        return ApiResponse(
            code=200,
            message="success",
            data=report_data,
            success=True,
            timestamp=time.time(),
        )

    except HTTPException as e:
        return ApiResponse(
            code=e.status_code,
            message=e.detail,
            data=None,
            success=False,
            timestamp=time.time(),
        )
    except Exception as e:
        return ApiResponse(
            code=500,
            message=f"生成 JSON 报告失败: {str(e)}",
            data=None,
            success=False,
            timestamp=time.time(),
        )


@router.get("/scans/{scan_id}/report/markdown")
async def get_scan_report_markdown(scan_id: str):
    """
    获取指定扫描会话的 Markdown 格式审计报告。

    请求方式: GET

    入参:
        - scan_id: 扫描会话标识符（路径参数）

    返回内容:
        - Content-Type: text/markdown
        - 审计报告的 Markdown 文本内容

    异常:
        - 404: scan_id 不存在
        - 500: 生成报告失败
    """
    try:
        result = _get_result_or_404(scan_id)
        markdown_content = build_markdown_report(result)

        return Response(content=markdown_content, media_type="text/markdown")

    except HTTPException as e:
        error_content = f"# 扫描不存在\n\n**错误信息:** {e.detail}"
        return Response(content=error_content, media_type="text/markdown", status_code=404)
    except Exception as e:
        error_content = f"# 报告生成失败\n\n**错误信息:** {str(e)}"
        return Response(content=error_content, media_type="text/markdown", status_code=500)


@router.get("/scans/{scan_id}/report/html")
async def get_scan_report_html(scan_id: str):
    """
    获取指定扫描会话的 HTML 格式审计报告。

    请求方式: GET

    入参:
        - scan_id: 扫描会话标识符（路径参数）

    返回内容:
        - Content-Type: text/html
        - 审计报告的 HTML 页面内容

    异常:
        - 404: scan_id 不存在
        - 500: 生成报告失败
    """
    try:
        result = _get_result_or_404(scan_id)
        html_content = build_html_report(result)

        return Response(content=html_content, media_type="text/html")

    except HTTPException as e:
        html_content = f"""
<!DOCTYPE html>
<html>
<head><title>扫描不存在</title><style>body{{font-family:Arial,sans-serif;margin:40px;color:#dc3545;}}</style></head>
<body><h1>扫描不存在</h1><p>错误信息: {e.detail}</p></body>
</html>
"""
        return Response(content=html_content, media_type="text/html", status_code=404)
    except Exception as e:
        html_content = f"""
<!DOCTYPE html>
<html>
<head><title>报告生成失败</title><style>body{{font-family:Arial,sans-serif;margin:40px;color:#dc3545;}}</style></head>
<body><h1>报告生成失败</h1><p>错误信息: {str(e)}</p></body>
</html>
"""
        return Response(content=html_content, media_type="text/html", status_code=500)


@router.get("/scans/{scan_id}/metadata", response_model=ApiResponse)
async def get_scan_metadata(scan_id: str):
    """
    获取指定扫描会话的元数据。

    元数据通常包含：
    - analyzer_runs: 分析器执行记录
    - analyzer_errors: 分析器错误记录
    - skipped_languages: 跳过的语言列表
    - 其他诊断数据

    请求方式: GET

    入参:
        - scan_id: 扫描会话标识符（路径参数）

    返回内容:
        - code: HTTP状态码
        - message: 响应消息
        - data: 元数据字典
        - success: 是否成功
        - timestamp: 响应时间戳

    异常:
        - 404: scan_id 不存在
        - 500: 获取元数据失败
    """
    try:
        result = _get_result_or_404(scan_id)
        metadata = result.metadata or {}

        return ApiResponse(
            code=200,
            message="success",
            data=metadata,
            success=True,
            timestamp=time.time(),
        )

    except HTTPException as e:
        return ApiResponse(
            code=e.status_code,
            message=e.detail,
            data=None,
            success=False,
            timestamp=time.time(),
        )
    except Exception as e:
        return ApiResponse(
            code=500,
            message=f"获取元数据失败: {str(e)}",
            data=None,
            success=False,
            timestamp=time.time(),
        )


@router.get("/scans/{scan_id}/analyzer-info", response_model=ApiResponse)
async def get_scan_analyzer_info(scan_id: str):
    """
    获取指定扫描会话的分析器执行详情。

    返回结构化信息：
    - analyzer_runs: 分析器执行记录列表
    - analyzer_errors: 分析器错误记录列表
    - skipped_languages: 跳过的语言记录列表

    请求方式: GET

    入参:
        - scan_id: 扫描会话标识符（路径参数）

    返回内容:
        - code: HTTP状态码
        - message: 响应消息
        - data: 分析器信息字典
        - success: 是否成功
        - timestamp: 响应时间戳

    异常:
        - 404: scan_id 不存在
        - 500: 获取分析器信息失败
    """
    try:
        result = _get_result_or_404(scan_id)
        analyzer_info = (result.metadata or {}).get("analyzer_info", {
            "analyzer_runs": [],
            "analyzer_errors": [],
            "skipped_languages": [],
        })

        return ApiResponse(
            code=200,
            message="success",
            data=analyzer_info,
            success=True,
            timestamp=time.time(),
        )

    except HTTPException as e:
        return ApiResponse(
            code=e.status_code,
            message=e.detail,
            data=None,
            success=False,
            timestamp=time.time(),
        )
    except Exception as e:
        return ApiResponse(
            code=500,
            message=f"获取分析器信息失败: {str(e)}",
            data=None,
            success=False,
            timestamp=time.time(),
        )


@router.get("/scans/{scan_id}/findings/view", response_model=ApiResponse)
async def get_scan_findings_view(scan_id: str):
    """
    获取指定扫描会话的 UI 友好漏洞视图。

    此端点返回合并了 RawFinding 和 JudgeDecision 数据的 FindingView 对象，
    为 UI 渲染提供稳定的契约。

    字段映射:
    - file_path -> file
    - start_line -> line
    - JudgeDecision.risk_score -> risk_score
    - JudgeDecision.verdict -> verdict

    请求方式: GET

    入参:
        - scan_id: 扫描会话标识符（路径参数）

    返回内容:
        - code: HTTP状态码
        - message: 响应消息
        - data: ScanView 对象，包含:
            - scan_id: 扫描标识符
            - status: "completed"
            - total_findings: 漏洞总数
            - confirmed_count: 确认的漏洞数
            - suspicious_count: 可疑的漏洞数
            - rejected_count: 排除的漏洞数
            - risk_score: 平均风险评分
            - languages: 扫描的语言列表
            - findings: FindingView 对象列表
        - success: 是否成功
        - timestamp: 响应时间戳

    异常:
        - 404: scan_id 不存在
        - 500: 获取视图失败
    """
    try:
        result = _get_result_or_404(scan_id)
        view = ScanView.from_audit_result(scan_id, result)

        return ApiResponse(
            code=200,
            message="success",
            data=view.to_dict(),
            success=True,
            timestamp=time.time(),
        )

    except HTTPException as e:
        return ApiResponse(
            code=e.status_code,
            message=e.detail,
            data=None,
            success=False,
            timestamp=time.time(),
        )
    except Exception as e:
        return ApiResponse(
            code=500,
            message=f"获取漏洞视图失败: {str(e)}",
            data=None,
            success=False,
            timestamp=time.time(),
        )