"""
漏洞列表 API 路由。

GET /findings — 返回最新扫描的漏洞列表（向后兼容）

功能说明:
- 获取最近一次扫描的所有漏洞记录
- 适用于前端快速展示漏洞列表
- 返回格式已适配前端数据读取需求

异常处理:
- 当不存在扫描记录时返回空列表而非抛出异常
"""

import time

from fastapi import APIRouter

from api.schemas import ApiResponse
from api.state import audit_state

router = APIRouter(tags=["findings"])


@router.get("/findings", response_model=ApiResponse)
async def list_findings():
    """
    获取最新扫描的漏洞列表。

    请求方式: GET
    无需请求参数

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
            "data": [
                {
                    "id": "finding-001",
                    "type": "SQL Injection",
                    "severity": "ERROR",
                    "confidence": "high",
                    "file_path": "app.py",
                    "start_line": 42,
                    "message": "Possible SQL injection detected",
                    "rule_id": "sql-injection-001"
                }
            ],
            "success": true,
            "timestamp": 1620000000.0
        }

    注意事项:
        - 如果没有扫描记录，返回空列表
        - 数据格式已适配前端表格渲染需求
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
        findings_data = [f.model_dump(mode="json") for f in result.findings]

        return ApiResponse(
            code=200,
            message="success",
            data=findings_data,
            success=True,
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