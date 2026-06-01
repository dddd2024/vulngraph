"""
证据包 API 路由。

GET /evidence — 返回最新扫描的证据包列表（向后兼容）

功能说明:
- 获取最近一次扫描的所有证据包
- 证据包包含漏洞的详细证据信息（代码片段、调用链等）
- 返回格式已适配前端证据展示需求

异常处理:
- 当不存在扫描记录时返回空列表而非抛出异常
"""

import time

from fastapi import APIRouter

from api.schemas import ApiResponse
from api.state import audit_state

router = APIRouter(tags=["evidence"])


@router.get("/evidence", response_model=ApiResponse)
async def list_evidence():
    """
    获取最新扫描的证据包列表。

    请求方式: GET
    无需请求参数

    返回内容:
        - code: HTTP状态码
        - message: 响应消息
        - data: 证据包列表
        - success: 是否成功
        - timestamp: 响应时间戳

    返回示例:
        {
            "code": 200,
            "message": "success",
            "data": [
                {
                    "id": "evidence-001",
                    "finding_id": "finding-001",
                    "snippets": [...],
                    "judge_decision": {...},
                    "confidence_score": 0.85
                }
            ],
            "success": true,
            "timestamp": 1620000000.0
        }

    注意事项:
        - 如果没有扫描记录，返回空列表
        - 证据包包含与漏洞相关的代码片段和裁决结果
    """
    try:
        # 获取最新扫描结果
        if not audit_state.has_result:
            return ApiResponse(
                code=200,
                message="success",
                data=[],
                success=True,
                timestamp=time.time(),
            )

        result = audit_state.get_latest()
        evidence_data = [e.model_dump(mode="json") for e in result.evidence]

        return ApiResponse(
            code=200,
            message="success",
            data=evidence_data,
            success=True,
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