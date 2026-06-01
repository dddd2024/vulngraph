"""
统计 API 路由。

GET /stats — 返回最新扫描的统计概览数据
"""

import time

from fastapi import APIRouter, HTTPException

from api.schemas import ApiResponse, StatsResponse
from api.state import audit_state

router = APIRouter(tags=["stats"])


def _calculate_risk_level(risk_score: float) -> str:
    """
    根据风险评分计算风险等级。
    
    Args:
        risk_score: 风险评分（0-100）
    
    Returns:
        风险等级: critical, high, medium, low
    """
    if risk_score >= 80:
        return "critical"
    elif risk_score >= 60:
        return "high"
    elif risk_score >= 40:
        return "medium"
    else:
        return "low"


def _build_stats_response() -> StatsResponse:
    """构建统计响应数据。"""
    try:
        # 获取历史扫描总数
        total_scans = len(audit_state.get_scan_ids())

        # 获取最新扫描结果
        result = audit_state.get_latest()

        # 检查是否存在扫描记录
        if not audit_state.has_result:
            return StatsResponse(
                total_scans=0,
                latest_scan_id=None,
                total_findings=0,
                severity_stats={"ERROR": 0, "WARN": 0, "INFO": 0},
                verdict_stats={"confirmed": 0, "suspicious": 0, "rejected": 0, "pending": 0},
                risk_score=0.0,
                risk_level="low",
                languages=[],
                trends=None,
            )

        # 统计漏洞严重程度分布
        severity_stats = {"ERROR": 0, "WARN": 0, "INFO": 0}
        for finding in result.findings:
            severity = getattr(finding, "severity", "INFO")
            if severity in severity_stats:
                severity_stats[severity] += 1

        # 统计裁决结果分布
        verdict_stats = {"confirmed": 0, "suspicious": 0, "rejected": 0, "pending": 0}
        for bundle in result.evidence:
            if bundle.judge_decision:
                verdict = getattr(bundle.judge_decision, "verdict", "pending")
                if verdict in verdict_stats:
                    verdict_stats[verdict] += 1

        # 获取最新扫描ID和风险评分
        latest_scan_id = audit_state._latest_scan_id
        risk_score = result.summary.risk_score if result.summary else 0.0
        risk_level = _calculate_risk_level(risk_score)

        return StatsResponse(
            total_scans=total_scans,
            latest_scan_id=latest_scan_id,
            total_findings=len(result.findings),
            severity_stats=severity_stats,
            verdict_stats=verdict_stats,
            risk_score=risk_score,
            risk_level=risk_level,
            languages=result.summary.languages if result.summary else [],
            trends=None,
        )

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"获取统计信息失败: {str(e)}")


@router.get("/stats", response_model=ApiResponse)
async def get_stats():
    """
    获取最新扫描的统计概览数据。

    请求方式: GET
    无需请求参数

    返回内容:
        - code: HTTP状态码
        - message: 响应消息
        - data: 统计数据，包含:
            - total_scans: 历史扫描总会话数
            - latest_scan_id: 最近一次扫描ID
            - total_findings: 最新扫描的漏洞总数
            - severity_stats: 按严重程度分布的漏洞数
            - verdict_stats: 按裁决结果分布的漏洞数
            - risk_score: 最新扫描的风险评分
            - risk_level: 风险等级（critical/high/medium/low）
            - languages: 扫描涉及的编程语言列表

    返回示例:
        {
            "code": 200,
            "message": "success",
            "data": {
                "total_scans": 5,
                "latest_scan_id": "abc123def456",
                "total_findings": 12,
                "severity_stats": {"ERROR": 3, "WARN": 7, "INFO": 2},
                "verdict_stats": {"confirmed": 5, "suspicious": 4, "rejected": 3},
                "risk_score": 67.5,
                "risk_level": "high",
                "languages": ["python", "javascript"]
            },
            "success": true,
            "timestamp": 1620000000.0
        }

    异常:
        500: 获取统计信息失败
    """
    try:
        data = _build_stats_response()
        return ApiResponse(
            code=200,
            message="success",
            data=data.model_dump(),
            success=True,
            timestamp=time.time(),
        )
    except Exception as e:
        return ApiResponse(
            code=500,
            message=f"获取统计信息失败: {str(e)}",
            data=None,
            success=False,
            timestamp=time.time(),
        )