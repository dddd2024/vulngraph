"""
Markdown report generator.

Generates Markdown-format audit reports from AuditResult objects.
"""

from audit_core.models import AuditResult


def build_markdown_report(result: AuditResult) -> str:
    """
    Build a Markdown report from an audit result.
    
    Args:
        result: The audit result to convert
        
    Returns:
        Markdown-formatted string
    """
    lines = []
    
    # Header
    lines.append("# Audit Report")
    lines.append("")
    
    # Summary
    lines.append("## Summary")
    lines.append("")
    lines.append(f"- **Total Code Units:** {result.summary.total_code_units}")
    lines.append(f"- **Total Findings:** {result.summary.total_findings}")
    lines.append(f"- **Total Evidence Bundles:** {result.summary.total_evidence_bundles}")
    lines.append(f"- **Overall Risk Score:** {result.summary.risk_score:.1f}")
    lines.append(f"- **Languages:** {', '.join(result.summary.languages) if result.summary.languages else 'N/A'}")
    lines.append("")
    
    # Findings
    lines.append("## Findings")
    lines.append("")
    
    if not result.findings:
        lines.append("No findings detected.")
    else:
        for i, finding in enumerate(result.findings, 1):
            lines.append(f"### {i}. {finding.type}")
            lines.append("")
            lines.append(f"- **Rule ID:** {finding.rule_id}")
            lines.append(f"- **Severity:** {finding.severity}")
            lines.append(f"- **Confidence:** {finding.confidence}")
            lines.append(f"- **Location:** {finding.file_path}:{finding.start_line}")
            lines.append(f"- **CWE:** {finding.cwe or 'N/A'}")
            lines.append("")
            lines.append(f"**Message:** {finding.message}")
            lines.append("")
    
    # Evidence
    lines.append("## Evidence")
    lines.append("")
    
    if not result.evidence:
        lines.append("No evidence bundles available.")
    else:
        for i, bundle in enumerate(result.evidence, 1):
            lines.append(f"### Evidence {i}")
            lines.append("")
            lines.append(f"- **Finding ID:** {bundle.finding.id}")
            lines.append(f"- **Type:** {bundle.finding.type}")
            
            if bundle.judge_decision:
                lines.append(f"- **Verdict:** {bundle.judge_decision.verdict}")
                lines.append(f"- **Risk Score:** {bundle.judge_decision.risk_score:.1f}")
            
            if bundle.snippets:
                lines.append("")
                lines.append("**Code Snippet:**")
                lines.append("```")
                for snippet in bundle.snippets[:1]:  # Show first snippet
                    lines.append(snippet.get("content", ""))
                lines.append("```")
            
            lines.append("")
    
    # Agent Analysis
    lines.append("## Agent Analysis")
    lines.append("")
    
    if not result.agent_logs:
        lines.append("No agent logs available.")
    else:
        lines.append(f"Total agent log entries: {len(result.agent_logs)}")
        lines.append("")
        
        for log in result.agent_logs:
            lines.append(f"- **{log.agent_name}** ({log.stage}): {log.message}")
        
        lines.append("")
    
    # Judge Decisions
    lines.append("## Judge Decisions")
    lines.append("")
    
    decisions = [e.judge_decision for e in result.evidence if e.judge_decision]
    
    if not decisions:
        lines.append("No judge decisions available.")
    else:
        for decision in decisions:
            lines.append(f"- **{decision.verdict.upper()}** (confidence: {decision.confidence}, risk: {decision.risk_score:.1f})")
            lines.append(f"  - {decision.reason}")
        
        lines.append("")
    
    return "\n".join(lines)
