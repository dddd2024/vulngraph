"""
HTML report generator.

Generates HTML-format audit reports from AuditResult objects.
"""

from audit_core.models import AuditResult
from report.markdown_report import build_markdown_report


def build_html_report(result: AuditResult) -> str:
    """
    Build an HTML report from an audit result.
    
    Args:
        result: The audit result to convert
        
    Returns:
        HTML-formatted string
    """
    # For Stage 1, we'll wrap the Markdown report in simple HTML
    markdown_content = build_markdown_report(result)
    
    # Convert Markdown to simple HTML (basic conversion)
    html_content = _markdown_to_html(markdown_content)
    
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Audit Report</title>
    <style>
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            line-height: 1.6;
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
            color: #333;
        }}
        h1 {{ color: #2c3e50; border-bottom: 2px solid #3498db; padding-bottom: 10px; }}
        h2 {{ color: #34495e; margin-top: 30px; }}
        h3 {{ color: #7f8c8d; }}
        pre {{
            background: #f8f9fa;
            padding: 15px;
            border-radius: 5px;
            overflow-x: auto;
            border-left: 4px solid #3498db;
        }}
        code {{
            background: #f8f9fa;
            padding: 2px 6px;
            border-radius: 3px;
            font-family: 'Courier New', monospace;
        }}
        ul {{ padding-left: 20px; }}
        .summary {{
            background: #ecf0f1;
            padding: 20px;
            border-radius: 8px;
            margin: 20px 0;
        }}
        .finding {{
            background: #fff;
            border: 1px solid #ddd;
            padding: 15px;
            margin: 10px 0;
            border-radius: 5px;
        }}
        .severity-error {{ border-left: 4px solid #e74c3c; }}
        .severity-warn {{ border-left: 4px solid #f39c12; }}
        .severity-info {{ border-left: 4px solid #3498db; }}
    </style>
</head>
<body>
{html_content}
</body>
</html>
"""


def _markdown_to_html(markdown: str) -> str:
    """
    Simple Markdown to HTML conversion.
    
    Args:
        markdown: Markdown text
        
    Returns:
        HTML text
    """
    lines = markdown.split("\n")
    html_lines = []
    in_code_block = False
    code_lines = []
    
    for line in lines:
        # Code blocks
        if line.startswith("```"):
            if in_code_block:
                # End code block
                html_lines.append("<pre><code>" + "\n".join(code_lines) + "</code></pre>")
                code_lines = []
                in_code_block = False
            else:
                # Start code block
                in_code_block = True
            continue
        
        if in_code_block:
            code_lines.append(line)
            continue
        
        # Headers
        if line.startswith("# "):
            html_lines.append(f"<h1>{line[2:]}</h1>")
        elif line.startswith("## "):
            html_lines.append(f"<h2>{line[3:]}</h2>")
        elif line.startswith("### "):
            html_lines.append(f"<h3>{line[4:]}</h3>")
        # List items
        elif line.startswith("- "):
            html_lines.append(f"<li>{_inline_format(line[2:])}</li>")
        # Empty lines
        elif line.strip() == "":
            html_lines.append("<br>")
        # Regular paragraphs
        else:
            html_lines.append(f"<p>{_inline_format(line)}</p>")
    
    return "\n".join(html_lines)


def _inline_format(text: str) -> str:
    """
    Format inline Markdown elements.
    
    Args:
        text: Text to format
        
    Returns:
        Formatted HTML
    """
    # Bold
    import re
    text = re.sub(r'\*\*(.*?)\*\*', r'<strong>\1</strong>', text)
    # Code
    text = re.sub(r'`(.*?)`', r'<code>\1</code>', text)
    return text
