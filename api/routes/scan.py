"""
扫描 API 路由。

POST /scan 是新审计流水线的主要入口点。
它委托给 AuditOrchestrator，使用 scan_id 存储结果，
并返回 scan_id 和完整的审计结果。

功能说明:
- 支持三种输入类型：代码片段、本地仓库路径、GitHub URL
- 返回统一格式的扫描结果
- 自动存储扫描会话，支持后续查询

异常处理:
- 输入类型错误返回 400 状态码
- 值错误返回 400 状态码
- 其他异常返回 500 状态码
"""

from fastapi import APIRouter, HTTPException

from api.schemas import ApiResponse, ScanRequest, ScanResponse
from api.state import audit_state
from audit_core.orchestrator import AuditOrchestrator

router = APIRouter(tags=["scan"])

# 共享的编排器实例
orchestrator = AuditOrchestrator()


def _run_scan(request: ScanRequest) -> tuple[str, dict]:
    """
    通过 AuditOrchestrator 执行扫描，使用 scan_id 持久化结果，并返回数据。

    Args:
        request: ScanRequest 对象，包含扫描参数

    Returns:
        元组 (scan_id, response_dict)，scan_id 是会话标识符，response_dict 是响应数据

    Raises:
        HTTPException: 当输入类型无效时抛出 400 错误
    """
    # 验证输入类型
    if request.input_type not in ("code", "path", "github"):
        raise HTTPException(
            status_code=400,
            detail=f"Invalid input_type: {request.input_type}. Must be 'code', 'path', or 'github'",
        )

    # 执行扫描
    result = orchestrator.scan(
        input_type=request.input_type,
        code=request.code,
        repo_path=request.repo_path,
        repo_url=request.repo_url,
        language=request.language if request.language != "auto" else None,
    )

    # 创建会话并获取 scan_id
    scan_id = audit_state.create_session(result)

    # 构建响应数据
    response_data = {
        "scan_id": scan_id,
        "summary": result.summary.model_dump(mode="json"),
        "findings": [f.model_dump(mode="json") for f in result.findings],
        "evidence": [e.model_dump(mode="json") for e in result.evidence],
        "agent_logs": [l.model_dump(mode="json") for l in result.agent_logs],
    }

    return scan_id, response_data


@router.post("/scan", response_model=ApiResponse)
async def scan(request: ScanRequest):
    """
    主扫描端点。

    接受代码片段、本地仓库路径或 GitHub URL，
    返回完整的审计结果，包括：
    - scan_id: 此扫描会话的唯一标识符
    - summary: 审计摘要统计信息
    - findings: 检测到的漏洞列表
    - evidence: 漏洞证据包列表
    - agent_logs: Agent 执行日志

    请求方式: POST

    入参 (JSON):
        - input_type: 输入类型，可选值: "code" | "path" | "github"
        - code: 代码片段（input_type="code" 时必填）
        - repo_path: 本地仓库路径（input_type="path" 时必填）
        - repo_url: GitHub 仓库 URL（input_type="github" 时必填）
        - language: 语言类型，可选值: "auto" | "python" | "javascript" | "java" | "cpp"

    返回内容:
        - code: HTTP状态码
        - message: 响应消息
        - data: 扫描结果对象，包含:
            - scan_id: 扫描会话标识符
            - summary: 摘要信息
            - findings: 漏洞列表
            - evidence: 证据包列表
            - agent_logs: Agent 日志列表
        - success: 是否成功
        - timestamp: 响应时间戳

    返回示例:
        {
            "code": 200,
            "message": "success",
            "data": {
                "scan_id": "scan-abc123",
                "summary": {
                    "total_code_units": 10,
                    "total_findings": 3,
                    "risk_score": 7.5,
                    "languages": ["python"],
                    "scanned_files": ["app.py"]
                },
                "findings": [...],
                "evidence": [...],
                "agent_logs": [...]
            },
            "success": true,
            "timestamp": 1620000000.0
        }

    使用 scan_id 查询详细结果:
        GET /scans/{scan_id}/findings
        GET /scans/{scan_id}/evidence
        GET /scans/{scan_id}/agents/logs
        GET /scans/{scan_id}/report/json

    异常:
        - 400: 输入类型无效或参数错误
        - 500: 扫描执行失败
    """
    import time

    try:
        _, response_data = _run_scan(request)
        return ApiResponse(
            code=200,
            message="success",
            data=response_data,
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
    except ValueError as e:
        return ApiResponse(
            code=400,
            message=str(e),
            data=None,
            success=False,
            timestamp=time.time(),
        )
    except Exception as e:
        return ApiResponse(
            code=500,
            message=f"Scan failed: {str(e)}",
            data=None,
            success=False,
            timestamp=time.time(),
        )