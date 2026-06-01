"""
报告生成 API 路由。

提供多种格式的审计报告导出功能：
- GET /report/json — 返回 JSON 格式报告（向后兼容）
- GET /report/markdown — 返回 Markdown 格式报告
- GET /report/html — 返回 HTML 格式报告

功能说明:
- 基于最新扫描结果生成审计报告
- 支持多种输出格式，满足不同使用场景
- JSON 格式适合程序消费
- Markdown 格式适合文档记录
- HTML 格式适合网页展示

异常处理:
- 当不存在扫描记录时返回空数据而非抛出异常
- 报告生成失败时返回统一错误响应
"""

import time

from fastapi import APIRouter, Response, HTTPException

from api.schemas import ApiResponse
from api.state import audit_state
from report.json_report import build_json_report
from report.markdown_report import build_markdown_report
from report.html_report import build_html_report

router = APIRouter(tags=["report"])


@router.get("/report/json", response_model=ApiResponse)
async def report_json():
    """
    获取最新扫描的 JSON 格式审计报告。

    请求方式: GET
    无需请求参数

    返回内容:
        - code: HTTP状态码
        - message: 响应消息
        - data: JSON 格式的审计报告
        - success: 是否成功
        - timestamp: 响应时间戳

    返回示例:
        {
            "code": 200,
            "message": "success",
            "data": {
                "summary": {...},
                "findings": [...],
                "evidence": [...],
                "agent_logs": [...]
            },
            "success": true,
            "timestamp": 1620000000.0
        }

    适用场景:
        - 程序间数据交换
        - API 客户端消费
        - 数据持久化存储
    """
    try:
        # 获取最新扫描结果
        if not audit_state.has_result:
            return ApiResponse(
                code=200,
                message="No scan result available",
                data={},
                success=True,
                timestamp=time.time(),
            )

        result = audit_state.get_latest()
        report_data = build_json_report(result)

        return ApiResponse(
            code=200,
            message="success",
            data=report_data,
            success=True,
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


@router.get("/report/markdown")
async def report_markdown():
    """
    获取最新扫描的 Markdown 格式审计报告。

    请求方式: GET
    无需请求参数

    返回内容:
        - Content-Type: text/markdown
        - 审计报告的 Markdown 文本内容

    适用场景:
        - 文档记录
        - README 文件
        - 版本控制提交说明
    """
    try:
        # 获取最新扫描结果
        if not audit_state.has_result:
            return Response(content="# 暂无扫描结果\n\n没有可用的审计报告数据。", media_type="text/markdown")

        result = audit_state.get_latest()
        markdown_content = build_markdown_report(result)

        return Response(content=markdown_content, media_type="text/markdown")

    except Exception as e:
        error_content = f"# 报告生成失败\n\n**错误信息:** {str(e)}"
        return Response(content=error_content, media_type="text/markdown", status_code=500)


@router.get("/report/html")
async def report_html():
    """
    获取最新扫描的 HTML 格式审计报告。

    请求方式: GET
    无需请求参数

    返回内容:
        - Content-Type: text/html
        - 审计报告的 HTML 页面内容

    适用场景:
        - 网页展示
        - 浏览器查看
        - 打印输出
    """
    try:
        # 获取最新扫描结果
        if not audit_state.has_result:
            html_content = """
<!DOCTYPE html>
<html>
<head><title>审计报告</title><style>body{font-family:Arial,sans-serif;margin:40px;text-align:center;color:#666;}</style></head>
<body><h1>暂无扫描结果</h1><p>没有可用的审计报告数据。</p></body>
</html>
"""
            return Response(content=html_content, media_type="text/html")

        result = audit_state.get_latest()
        html_content = build_html_report(result)

        return Response(content=html_content, media_type="text/html")

    except Exception as e:
        html_content = f"""
<!DOCTYPE html>
<html>
<head><title>报告生成失败</title><style>body{{font-family:Arial,sans-serif;margin:40px;color:#dc3545;}}</style></head>
<body><h1>报告生成失败</h1><p>错误信息: {str(e)}</p></body>
</html>
"""
        return Response(content=html_content, media_type="text/html", status_code=500)