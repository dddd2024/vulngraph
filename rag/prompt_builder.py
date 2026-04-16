from typing import Any


def build_prompt(vuln: dict[str, Any], context: str, impact: list[dict[str, Any]]) -> str:
    return f"""You are a security patch generator.

Vulnerability type: {vuln["type"]}
Location: {vuln["file"]}:{vuln["line"]}
Impact paths: {impact}

Relevant context:
{context}

Return strict JSON:
{{
  "reason": "...",
  "patch": "... unified diff ...",
  "test": "... pytest test file ..."
}}
"""

