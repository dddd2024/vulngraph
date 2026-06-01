"""
Agent 日志 API 路由。

GET /agents/logs — 返回最新扫描的 Agent 执行日志（向后兼容）

功能说明:
- 获取最近一次扫描的所有 Agent 执行日志
- 日志包含 ReconAgent、AnalysisAgent、JudgeAgent 的执行记录
- 返回格式已适配前端日志展示需求

异常处理:
- 当不存在扫描记录时返回空列表而非抛出异常
"""

import time

from fastapi import APIRouter

from api.schemas import ApiResponse
from api.state import audit_state

router = APIRouter(tags=["agents"])


@router.get("/agents/logs", response_model=ApiResponse)
async def list_agent_logs():
    """
    获取最新扫描的 Agent 执行日志。

    请求方式: GET
    无需请求参数

    返回内容:
        - code: HTTP状态码
        - message: 响应消息
        - data: Agent 日志列表
        - success: 是否成功
        - timestamp: 响应时间戳

    返回示例:
        {
            "code": 200,
            "message": "success",
            "data": [
                {
                    "agent_name": "ReconAgent",
                    "timestamp": 1620000000.0,
                    "level": "INFO",
                    "message": "Starting reconnaissance...",
                    "duration_ms": 1200
                }
            ],
            "success": true,
            "timestamp": 1620000000.0
        }

    注意事项:
        - 如果没有扫描记录，返回空列表
        - 日志包含各 Agent 的执行时间、级别和消息
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
        logs_data = [l.model_dump(mode="json") for l in result.agent_logs]

        return ApiResponse(
            code=200,
            message="success",
            data=logs_data,
            success=True,
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