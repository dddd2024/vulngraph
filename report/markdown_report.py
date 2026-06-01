"""
Markdown 审计报告生成器。

提供从审计结果生成标准 Markdown 报告的功能。

主要功能:
- 支持从 AuditResult 对象生成报告（build_markdown_report）
- 支持从字典格式输入生成报告（generate_markdown_report_from_dict）
- 包含扫描基础信息、漏洞统计、详细漏洞信息
- 自动格式化代码片段和表格
- 支持修复建议的展示
"""

from typing import Any, Dict, List, Optional

from audit_core.models import AuditResult


def generate_markdown_report_from_dict(audit_result: Dict[str, Any]) -> str:
    """
    从审计结果字典生成标准 Markdown 审计报告。

    Args:
        audit_result: 审计结果字典，包含以下结构:
            {
                "summary": {
                    "total_code_units": int,
                    "total_findings": int,
                    "total_evidence_bundles": int,
                    "risk_score": float,
                    "languages": list[str],
                    "scanned_files": list[str]
                },
                "findings": [
                    {
                        "id": str,
                        "type": str,           # 漏洞类型
                        "rule_id": str,        # 规则ID
                        "cwe": str,            # CWE编号
                        "severity": str,       # 风险等级
                        "confidence": str,     # 置信度
                        "file_path": str,      # 文件路径
                        "start_line": int,     # 起始行号
                        "end_line": int,       # 结束行号（可选）
                        "message": str,        # 漏洞描述
                        "suggestion": str      # 修复建议（可选）
                    }
                ],
                "evidence": [
                    {
                        "finding_id": str,
                        "snippets": [
                            {
                                "content": str,      # 代码片段内容
                                "file_path": str,    # 文件路径
                                "start_line": int    # 起始行号
                            }
                        ],
                        "judge_decision": {
                            "verdict": str,        # 裁决结果
                            "risk_score": float,   # 风险评分
                            "confidence": str,     # 置信度
                            "reason": str          # 裁决理由
                        }
                    }
                ]
            }

    Returns:
        Markdown 格式的审计报告字符串
    """
    lines = []

    # ============ 报告标题 ============
    lines.append("# 安全审计报告")
    lines.append("")
    lines.append("---")
    lines.append("")

    # ============ 扫描基础信息 ============
    summary = audit_result.get("summary", {})
    lines.append("## 一、扫描概览")
    lines.append("")
    
    # 生成概览表格
    overview_table = [
        ["项目", "详情"],
        ["---", "---"],
        ["代码单元总数", str(summary.get("total_code_units", 0))],
        ["检测到漏洞数", str(summary.get("total_findings", 0))],
        ["证据包数量", str(summary.get("total_evidence_bundles", 0))],
        ["综合风险评分", f"{summary.get('risk_score', 0.0):.1f}/100"],
        ["扫描语言", ", ".join(summary.get("languages", ["N/A"]))],
    ]
    
    for row in overview_table:
        lines.append("| " + " | ".join(row) + " |")
    lines.append("")

    # 扫描文件列表
    scanned_files = summary.get("scanned_files", [])
    if scanned_files:
        lines.append("### 扫描文件列表")
        lines.append("")
        for file in scanned_files[:10]:  # 最多显示10个文件
            lines.append(f"- `{file}`")
        if len(scanned_files) > 10:
            lines.append(f"- ... 还有 {len(scanned_files) - 10} 个文件")
        lines.append("")

    # ============ 漏洞数量统计 ============
    findings = audit_result.get("findings", [])
    lines.append("## 二、漏洞统计")
    lines.append("")

    # 按严重程度统计
    severity_counts = {}
    for finding in findings:
        severity = finding.get("severity", "UNKNOWN")
        severity_counts[severity] = severity_counts.get(severity, 0) + 1

    if severity_counts:
        lines.append("### 按严重程度分布")
        lines.append("")
        
        # 定义严重程度优先级和颜色
        severity_order = ["ERROR", "WARN", "INFO", "UNKNOWN"]
        severity_colors = {
            "ERROR": "🔴",
            "WARN": "🟡",
            "INFO": "🟢",
            "UNKNOWN": "⚪"
        }
        
        for severity in severity_order:
            if severity in severity_counts:
                count = severity_counts[severity]
                lines.append(f"- {severity_colors.get(severity, '')} **{severity}**: {count} 个")
        
        lines.append("")

    # 按类型统计
    type_counts = {}
    for finding in findings:
        finding_type = finding.get("type", "Unknown")
        type_counts[finding_type] = type_counts.get(finding_type, 0) + 1

    if type_counts:
        lines.append("### 按漏洞类型分布")
        lines.append("")
        
        for finding_type, count in sorted(type_counts.items(), key=lambda x: x[1], reverse=True):
            lines.append(f"- **{finding_type}**: {count} 个")
        
        lines.append("")

    # ============ 风险等级评估 ============
    risk_score = summary.get("risk_score", 0.0)
    lines.append("## 三、风险等级评估")
    lines.append("")
    
    # 根据风险评分确定等级
    if risk_score >= 80:
        risk_level = "🔴 高危"
        risk_desc = "系统存在严重安全漏洞，建议立即修复"
    elif risk_score >= 50:
        risk_level = "🟡 中危"
        risk_desc = "系统存在中等风险漏洞，建议尽快修复"
    elif risk_score >= 20:
        risk_level = "🟢 低危"
        risk_desc = "系统存在低风险漏洞，建议定期修复"
    else:
        risk_level = "✅ 安全"
        risk_desc = "系统安全状况良好"
    
    lines.append(f"- **综合风险等级**: {risk_level}")
    lines.append(f"- **风险评分**: {risk_score:.1f}/100")
    lines.append(f"- **评估说明**: {risk_desc}")
    lines.append("")

    # ============ 漏洞详情列表 ============
    lines.append("## 四、漏洞详情")
    lines.append("")

    if not findings:
        lines.append("### 未检测到漏洞")
        lines.append("")
        lines.append("✅ 代码安全审计通过，未发现安全漏洞。")
        lines.append("")
    else:
        # 获取证据包映射（用于匹配代码片段）
        evidence_map = {}
        for evidence in audit_result.get("evidence", []):
            finding_id = evidence.get("finding_id")
            if finding_id:
                evidence_map[finding_id] = evidence

        for idx, finding in enumerate(findings, 1):
            # 获取对应的证据包
            evidence = evidence_map.get(finding.get("id"))
            
            lines.append(f"### {idx}. {finding.get('type', 'Unknown')}")
            lines.append("")
            
            # 基本信息表格
            lines.append("| 项目 | 详情 |")
            lines.append("|------|------|")
            lines.append(f"| **规则ID** | `{finding.get('rule_id', 'N/A')}` |")
            lines.append(f"| **CWE编号** | `{finding.get('cwe', 'N/A')}` |")
            lines.append(f"| **风险等级** | {_get_severity_badge(finding.get('severity', 'UNKNOWN'))} |")
            lines.append(f"| **置信度** | {finding.get('confidence', 'N/A')} |")
            
            file_path = finding.get("file_path", "N/A")
            start_line = finding.get("start_line", 0)
            end_line = finding.get("end_line")
            if end_line:
                lines.append(f"| **代码位置** | `{file_path}:{start_line}-{end_line}` |")
            else:
                lines.append(f"| **代码位置** | `{file_path}:{start_line}` |")
            
            lines.append("")

            # 漏洞描述
            lines.append("**漏洞描述:**")
            lines.append("")
            lines.append(f"> {finding.get('message', '无描述')}")
            lines.append("")

            # 代码片段（从证据包获取）
            if evidence:
                snippets = evidence.get("snippets", [])
                if snippets:
                    lines.append("**代码片段:**")
                    lines.append("")
                    snippet = snippets[0]
                    code_content = snippet.get("content", "")
                    code_file = snippet.get("file_path", file_path)
                    code_line = snippet.get("start_line", start_line)
                    
                    lines.append(f"```python")
                    lines.append(code_content)
                    lines.append(f"```")
                    lines.append(f"*文件: {code_file}，行号: {code_line}*")
                    lines.append("")

            # 修复建议
            suggestion = finding.get("suggestion")
            if not suggestion and evidence:
                suggestion = evidence.get("judge_decision", {}).get("reason")
            
            if suggestion:
                lines.append("**修复建议:**")
                lines.append("")
                lines.append(f"> {suggestion}")
            else:
                lines.append("**修复建议:**")
                lines.append("")
                lines.append("> 建议根据漏洞类型进行相应修复。")
            
            lines.append("")
            
            # 分隔线
            if idx < len(findings):
                lines.append("---")
                lines.append("")

    # ============ 报告结尾 ============
    lines.append("---")
    lines.append("")
    lines.append("*报告生成时间: 自动生成*")
    lines.append("*工具: VulnPatch 源代码安全审计平台*")

    return "\n".join(lines)


def _get_severity_badge(severity: str) -> str:
    """
    根据严重程度返回带图标的标签。

    Args:
        severity: 严重程度字符串（ERROR, WARN, INFO, UNKNOWN）

    Returns:
        带图标的严重程度标签
    """
    severity_map = {
        "ERROR": "🔴 高危",
        "WARN": "🟡 中危",
        "INFO": "🟢 低危",
        "UNKNOWN": "⚪ 未知"
    }
    return severity_map.get(severity.upper(), f"⚪ {severity}")


def build_markdown_report(result: AuditResult) -> str:
    """
    从 AuditResult 对象生成 Markdown 报告（向后兼容）。

    此函数保持与原有 API 的兼容性，将 AuditResult 对象转换为字典后调用
    generate_markdown_report_from_dict 生成报告。

    Args:
        result: AuditResult 对象，包含审计结果数据

    Returns:
        Markdown 格式的审计报告字符串
    """
    # 将 AuditResult 转换为字典格式
    audit_dict = result.to_dict()
    
    # 添加证据包的 finding_id 映射（用于匹配代码片段）
    evidence_list = audit_dict.get("evidence", [])
    for evidence in evidence_list:
        if "finding" in evidence:
            evidence["finding_id"] = evidence["finding"].get("id")
    
    return generate_markdown_report_from_dict(audit_dict)


# ==================== 测试示例 ====================
if __name__ == "__main__":
    # 模拟审计结果数据
    sample_audit_result = {
        "summary": {
            "total_code_units": 5,
            "total_findings": 3,
            "total_evidence_bundles": 3,
            "risk_score": 72.5,
            "languages": ["Python"],
            "scanned_files": ["app.py", "utils.py", "config.py", "auth.py", "api/routes/scan.py"]
        },
        "findings": [
            {
                "id": "finding-001",
                "type": "SQL Injection",
                "rule_id": "sql-injection-001",
                "cwe": "CWE-89",
                "severity": "ERROR",
                "confidence": "high",
                "file_path": "app.py",
                "start_line": 42,
                "end_line": 45,
                "message": "检测到 SQL 注入漏洞：用户输入直接拼接到 SQL 查询语句中，未进行参数化处理。",
                "suggestion": "使用参数化查询或 ORM 框架，避免直接拼接 SQL 语句。"
            },
            {
                "id": "finding-002",
                "type": "Path Traversal",
                "rule_id": "path-traversal-001",
                "cwe": "CWE-22",
                "severity": "ERROR",
                "confidence": "medium",
                "file_path": "utils.py",
                "start_line": 15,
                "message": "检测到路径遍历漏洞：用户输入直接用于文件路径拼接，可能导致任意文件读取。",
                "suggestion": "对用户输入进行严格的路径校验，使用白名单机制限制可访问的目录。"
            },
            {
                "id": "finding-003",
                "type": "Hardcoded Secret",
                "rule_id": "hardcoded-secret-001",
                "cwe": "CWE-798",
                "severity": "WARN",
                "confidence": "high",
                "file_path": "config.py",
                "start_line": 23,
                "message": "检测到硬编码密钥：代码中包含明文密码或 API 密钥。",
                "suggestion": "将敏感配置存储在环境变量或专用配置管理系统中。"
            }
        ],
        "evidence": [
            {
                "id": "evidence-001",
                "finding_id": "finding-001",
                "snippets": [
                    {
                        "content": "def get_user(username):\n    query = f\"SELECT * FROM users WHERE username = '{username}'\"\n    cursor.execute(query)",
                        "file_path": "app.py",
                        "start_line": 42
                    }
                ],
                "judge_decision": {
                    "verdict": "confirmed",
                    "risk_score": 95.0,
                    "confidence": "high",
                    "reason": "SQL 查询直接使用字符串格式化拼接用户输入，存在明显的 SQL 注入风险。"
                }
            },
            {
                "id": "evidence-002",
                "finding_id": "finding-002",
                "snippets": [
                    {
                        "content": "def read_file(filename):\n    with open(f'/data/{filename}', 'r') as f:\n        return f.read()",
                        "file_path": "utils.py",
                        "start_line": 15
                    }
                ],
                "judge_decision": {
                    "verdict": "confirmed",
                    "risk_score": 85.0,
                    "confidence": "medium",
                    "reason": "用户输入直接拼接到文件路径中，未做路径规范化处理。"
                }
            },
            {
                "id": "evidence-003",
                "finding_id": "finding-003",
                "snippets": [
                    {
                        "content": "SECRET_KEY = 'my_secret_password_123'",
                        "file_path": "config.py",
                        "start_line": 23
                    }
                ],
                "judge_decision": {
                    "verdict": "confirmed",
                    "risk_score": 60.0,
                    "confidence": "high",
                    "reason": "代码中包含硬编码的敏感信息，可能被泄露。"
                }
            }
        ],
        "agent_logs": []
    }

    # 生成报告
    report = generate_markdown_report_from_dict(sample_audit_result)
    
    # 保存到文件
    with open("sample_report.md", "w", encoding="utf-8") as f:
        f.write(report)
    
    # 打印报告（处理Windows编码问题）
    try:
        print(report)
    except UnicodeEncodeError:
        # 移除emoji字符后再打印
        report_no_emoji = report.encode('ascii', 'replace').decode('ascii')
        print(report_no_emoji)
    
    print("\n\n报告已保存到: sample_report.md")