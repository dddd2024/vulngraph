"""
漏洞过滤 API 路由。

GET /findings/filter — 返回过滤后的漏洞列表
支持按严重程度、漏洞类型、编程语言、裁决结果过滤，支持分页
"""

import time
from typing import Optional

from fastapi import APIRouter, HTTPException, Query

from api.schemas import ApiResponse, FindingsFilterResponse
from api.state import audit_state

router = APIRouter(tags=["findings"])


@router.get("/findings/filter", response_model=ApiResponse)
async def filter_findings(
    severity: Optional[str] = Query(
        None,
        description="漏洞严重程度过滤，支持: ERROR, WARN, INFO"
    ),
    vuln_type: Optional[str] = Query(
        None,
        description="漏洞类型过滤，如: SQL Injection, XSS"
    ),
    language: Optional[str] = Query(
        None,
        description="编程语言过滤，如: python, javascript"
    ),
    verdict: Optional[str] = Query(
        None,
        description="裁决结果过滤，支持: confirmed, suspicious, rejected, pending"
    ),
    min_risk_score: Optional[float] = Query(
        None,
        ge=0.0,
        le=100.0,
        description="最低风险分数过滤，范围: 0.0 - 100.0"
    ),
    page: int = Query(1, ge=1, description="页码，从1开始"),
    size: int = Query(10, ge=1, le=100, description="每页数量，最大100"),
):
    """
    过滤漏洞列表。

    请求方式: GET

    入参（Query 参数）:
        - severity: 漏洞严重程度，支持 ERROR / WARN / INFO（可选）
        - vuln_type: 漏洞类型，如 SQL Injection、XSS（可选，支持模糊匹配）
        - language: 编程语言，如 python、javascript（可选）
        - verdict: 裁决结果，支持 confirmed / suspicious / rejected / pending（可选）
        - min_risk_score: 最低风险分数，范围 0.0 - 100.0（可选）
        - page: 页码，从1开始（默认1）
        - size: 每页数量，最大100（默认10）

    出参:
        - code: HTTP状态码
        - message: 响应消息
        - data: 过滤结果，包含:
            - total: 符合条件的漏洞总数
            - page: 当前页码
            - size: 每页数量
            - total_pages: 总页数
            - filters_applied: 本次过滤使用的条件
            - findings: 漏洞列表（分页后）
            - summary: 统计摘要

    调用示例:
        GET /findings/filter?severity=ERROR&page=1&size=10
        GET /findings/filter?verdict=confirmed&min_risk_score=60
        GET /findings/filter?vuln_type=SQL Injection&language=python

    返回示例:
        {
            "code": 200,
            "message": "success",
            "data": {
                "total": 15,
                "page": 1,
                "size": 10,
                "total_pages": 2,
                "filters_applied": {"severity": "ERROR"},
                "findings": [...],
                "summary": {"total_error": 3, "total_warn": 8, "total_info": 4}
            },
            "success": true,
            "timestamp": 1620000000.0
        }

    异常:
        404: 当不存在扫描记录时
    """
    try:
        # 获取最新扫描结果
        if not audit_state.has_result:
            return ApiResponse(
                code=404,
                message="No scan result available",
                data=None,
                success=False,
                timestamp=time.time(),
            )

        result = audit_state.get_latest()

        # 构建裁决结果映射（finding_id -> verdict）
        verdict_map = {}
        risk_score_map = {}
        for bundle in result.evidence:
            if bundle.finding:
                finding_id = bundle.finding.id
                if bundle.judge_decision:
                    verdict_map[finding_id] = bundle.judge_decision.verdict
                    risk_score_map[finding_id] = bundle.judge_decision.risk_score
                else:
                    verdict_map[finding_id] = "pending"
                    risk_score_map[finding_id] = 0.0

        # 应用过滤条件
        filtered_findings = []
        applied_filters = {}

        for finding in result.findings:
            # 严重程度过滤
            if severity:
                if getattr(finding, "severity", None) != severity:
                    continue
                applied_filters["severity"] = severity

            # 漏洞类型过滤（支持模糊匹配）
            if vuln_type:
                finding_type = getattr(finding, "type", "") or ""
                if vuln_type.lower() not in finding_type.lower():
                    continue
                applied_filters["vuln_type"] = vuln_type

            # 裁决结果过滤
            if verdict:
                finding_verdict = verdict_map.get(finding.id, "pending")
                if finding_verdict != verdict:
                    continue
                applied_filters["verdict"] = verdict

            # 最低风险分数过滤
            if min_risk_score is not None:
                finding_risk_score = risk_score_map.get(finding.id, 0.0)
                if finding_risk_score < min_risk_score:
                    continue
                applied_filters["min_risk_score"] = min_risk_score

            # 语言过滤（通过 file_path 或 metadata 判断）
            if language:
                finding_lang = getattr(finding, "language", None)
                if finding_lang:
                    finding_lang = finding_lang.lower()
                    if language.lower() != finding_lang:
                        file_path = getattr(finding, "file_path", "") or ""
                        lang_extensions = {
                            "python": [".py"],
                            "javascript": [".js", ".mjs"],
                            "typescript": [".ts", ".tsx"],
                            "java": [".java"],
                            "c": [".c", ".h"],
                            "cpp": [".cpp", ".cc", ".cxx", ".hpp"],
                        }
                        exts = lang_extensions.get(language.lower(), [])
                        if not any(file_path.endswith(ext) for ext in exts):
                            continue
                applied_filters["language"] = language

            # 通过所有过滤条件的漏洞
            filtered_findings.append(finding.model_dump(mode="json"))

        # 计算分页
        total = len(filtered_findings)
        total_pages = (total + size - 1) // size
        start_idx = (page - 1) * size
        end_idx = start_idx + size
        paginated_findings = filtered_findings[start_idx:end_idx]

        # 统计摘要
        summary = {}
        if result.summary:
            summary = {
                "total_findings": len(result.findings),
                "risk_score": result.summary.risk_score,
            }

        response_data = FindingsFilterResponse(
            total=total,
            page=page,
            size=size,
            total_pages=total_pages,
            filters_applied=applied_filters,
            findings=paginated_findings,
            summary=summary,
        )

        return ApiResponse(
            code=200,
            message="success",
            data=response_data.model_dump(),
            success=True,
            timestamp=time.time(),
        )

    except Exception as e:
        return ApiResponse(
            code=500,
            message=f"漏洞过滤失败: {str(e)}",
            data=None,
            success=False,
            timestamp=time.time(),
        )