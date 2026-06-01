"""
API request/response schemas.

Defines Pydantic models for API requests and responses.
"""

from pydantic import BaseModel, Field
from typing import Literal, Optional, Any


class ScanRequest(BaseModel):
    """Request model for /scan endpoint."""
    input_type: Literal["code", "path", "github"] = Field(
        ..., description="Type of input: 'code', 'path', or 'github'"
    )
    code: Optional[str] = None
    repo_path: Optional[str] = None
    repo_url: Optional[str] = None
    language: str = "auto"


class ScanResponse(BaseModel):
    """Response model for /scan endpoint."""
    scan_id: str = Field(..., description="Unique identifier for this scan session")
    summary: dict
    findings: list[dict]
    evidence: list[dict]
    agent_logs: list[dict]


class HealthResponse(BaseModel):
    """Response model for /health endpoint."""
    status: str


class ApiResponse(BaseModel):
    """
    统一API响应格式。
    
    适配前端和报告模块的数据读取需求：
    - code: HTTP状态码
    - message: 响应消息
    - data: 实际数据
    - success: 是否成功
    - timestamp: 响应时间戳
    """
    code: int = Field(200, description="HTTP状态码")
    message: str = Field("success", description="响应消息")
    data: Optional[Any] = Field(None, description="实际数据")
    success: bool = Field(True, description="操作是否成功")
    timestamp: float = Field(0.0, description="响应时间戳")


class FindingsFilterResponse(BaseModel):
    """
    漏洞过滤响应模型。
    
    字段说明：
    - total: 符合条件的漏洞总数
    - page: 当前页码（从1开始）
    - size: 每页数量
    - total_pages: 总页数
    - filters_applied: 应用的过滤条件
    - findings: 漏洞列表
    - summary: 统计摘要
    """
    total: int = Field(0, description="符合条件的漏洞总数")
    page: int = Field(1, description="当前页码")
    size: int = Field(10, description="每页数量")
    total_pages: int = Field(0, description="总页数")
    filters_applied: dict = Field({}, description="应用的过滤条件")
    findings: list[dict] = Field([], description="漏洞列表")
    summary: dict = Field({}, description="统计摘要")


class ScanListResponse(BaseModel):
    """
    扫描会话列表响应模型。
    
    字段说明：
    - total: 总会话数
    - page: 当前页码
    - size: 每页数量
    - total_pages: 总页数
    - scans: 会话列表
    """
    total: int = Field(0, description="总会话数")
    page: int = Field(1, description="当前页码")
    size: int = Field(10, description="每页数量")
    total_pages: int = Field(0, description="总页数")
    scans: list[dict] = Field([], description="会话列表")


class StatsResponse(BaseModel):
    """
    统计信息响应模型。
    
    字段说明：
    - total_scans: 历史扫描总会话数
    - latest_scan_id: 最近一次扫描ID
    - total_findings: 最新扫描的漏洞总数
    - severity_stats: 按严重程度分布的漏洞数
    - verdict_stats: 按裁决结果分布的漏洞数
    - risk_score: 最新扫描的风险评分
    - risk_level: 风险等级（low/medium/high/critical）
    - languages: 扫描涉及的编程语言列表
    - trends: 趋势数据（可选）
    """
    total_scans: int = Field(0, description="历史扫描总会话数")
    latest_scan_id: Optional[str] = Field(None, description="最近一次扫描ID")
    total_findings: int = Field(0, description="最新扫描的漏洞总数")
    severity_stats: dict = Field({}, description="按严重程度分布的漏洞数")
    verdict_stats: dict = Field({}, description="按裁决结果分布的漏洞数")
    risk_score: float = Field(0.0, description="最新扫描的风险评分")
    risk_level: str = Field("low", description="风险等级")
    languages: list[str] = Field([], description="扫描涉及的编程语言列表")
    trends: Optional[dict] = Field(None, description="趋势数据")