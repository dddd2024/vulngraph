"""
扫描会话管理 API 路由。

GET  /scans        — 返回所有扫描会话列表（支持分页）
DELETE /scans/{scan_id} — 删除指定扫描会话
"""

import time
from typing import Optional

from fastapi import APIRouter, HTTPException, Query

from api.schemas import ApiResponse, ScanListResponse
from api.state import audit_state

router = APIRouter(tags=["scans"])


@router.get("/scans", response_model=ApiResponse)
async def list_scans(
    page: int = Query(1, ge=1, description="页码，从1开始"),
    size: int = Query(10, ge=1, le=100, description="每页数量，最大100"),
):
    """
    获取所有扫描会话列表。

    请求方式: GET

    入参（Query 参数）:
        - page: 页码，从1开始（默认1）
        - size: 每页数量，最大100（默认10）

    出参:
        - code: HTTP状态码
        - message: 响应消息
        - data: 会话列表数据，包含:
            - total: 总会话数
            - page: 当前页码
            - size: 每页数量
            - total_pages: 总页数
            - scans: 会话列表，每项包含:
                - scan_id: 会话ID
                - total_findings: 该次扫描的漏洞数
                - risk_score: 该次扫描的风险评分
                - languages: 扫描的语言列表
                - timestamp: 扫描时间（如果可用）

    调用示例:
        GET /scans?page=1&size=10

    返回示例:
        {
            "code": 200,
            "message": "success",
            "data": {
                "total": 3,
                "page": 1,
                "size": 10,
                "total_pages": 1,
                "scans": [
                    {"scan_id": "abc123", "total_findings": 5, "risk_score": 72.5, "languages": ["python"]},
                    {"scan_id": "def456", "total_findings": 8, "risk_score": 45.0, "languages": ["javascript", "python"]}
                ]
            },
            "success": true,
            "timestamp": 1620000000.0
        }
    """
    try:
        scan_ids = audit_state.get_scan_ids()
        scans = []

        for scan_id in scan_ids:
            result = audit_state.get_by_id(scan_id)
            if result:
                scans.append({
                    "scan_id": scan_id,
                    "total_findings": len(result.findings),
                    "risk_score": result.summary.risk_score if result.summary else 0.0,
                    "languages": result.summary.languages if result.summary else [],
                    "timestamp": None,
                })

        # 计算分页
        total = len(scans)
        total_pages = (total + size - 1) // size
        start_idx = (page - 1) * size
        end_idx = start_idx + size
        paginated_scans = scans[start_idx:end_idx]

        response_data = ScanListResponse(
            total=total,
            page=page,
            size=size,
            total_pages=total_pages,
            scans=paginated_scans,
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
            message=f"获取扫描列表失败: {str(e)}",
            data=None,
            success=False,
            timestamp=time.time(),
        )


@router.delete("/scans/{scan_id}", response_model=ApiResponse)
async def delete_scan(scan_id: str):
    """
    删除指定的扫描会话。

    请求方式: DELETE

    入参:
        - scan_id: 扫描会话ID（路径参数）

    出参:
        - code: HTTP状态码
        - message: 响应消息
        - data: 被删除的会话信息
        - success: 是否删除成功

    调用示例:
        DELETE /scans/abc123def456

    返回示例:
        {
            "code": 200,
            "message": "Scan session deleted successfully",
            "data": {"scan_id": "abc123def456"},
            "success": true,
            "timestamp": 1620000000.0
        }

    异常:
        404: 当指定的 scan_id 不存在时
    """
    try:
        # 检查会话是否存在
        if not audit_state.has_scan(scan_id):
            return ApiResponse(
                code=404,
                message=f"Scan session not found: {scan_id}",
                data=None,
                success=False,
                timestamp=time.time(),
            )

        # 执行删除
        with audit_state._lock:
            if audit_state._latest_scan_id == scan_id:
                audit_state._latest_scan_id = None

            if scan_id in audit_state._sessions:
                del audit_state._sessions[scan_id]

        return ApiResponse(
            code=200,
            message="Scan session deleted successfully",
            data={"scan_id": scan_id},
            success=True,
            timestamp=time.time(),
        )

    except Exception as e:
        return ApiResponse(
            code=500,
            message=f"删除扫描会话失败: {str(e)}",
            data=None,
            success=False,
            timestamp=time.time(),
        )