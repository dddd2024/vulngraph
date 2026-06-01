"""
SSTI (Server-Side Template Injection) detection engine for Python.

Detects unsafe template rendering with user-controlled input in:
- Jinja2
- Tornado Templates
- Mako
- Django Templates (limited)
- String.Template
"""

import ast
import re
from typing import List, Optional

from audit_core.models import RawFinding, CodeUnit


class SSTIEngine:
    """Engine for detecting Server-Side Template Injection vulnerabilities."""
    
    # Template engines and their render methods
    TEMPLATE_PATTERNS = {
        'jinja2': {
            'imports': ['jinja2', 'Jinja2', 'Template', 'Environment'],
            'render_methods': ['render', 'render_string', 'render_template'],
            'compile_methods': ['from_string', 'compile'],
        },
        'mako': {
            'imports': ['mako', 'Mako', 'Template'],
            'render_methods': ['render'],
            'compile_methods': [],
        },
        'tornado': {
            'imports': ['tornado.template', 'Template'],
            'render_methods': ['generate', 'render'],
            'compile_methods': [],
        },
        'django': {
            'imports': ['django.template', 'Template'],
            'render_methods': ['render'],
            'compile_methods': [],
        },
        'string': {
            'imports': ['string', 'Template'],
            'render_methods': ['substitute', 'safe_substitute'],
            'compile_methods': [],
        },
    }
    
    # User input sources
    USER_INPUT_PATTERNS = [
        r'request\.(?:args|form|json|data|files|cookies|headers)',
        r'req\.(?:query|body|params)',
        r'input\s*\(',
        r'sys\.argv',
        r'os\.environ',
    ]
    
    def scan_code(self, code: str, filepath: str = "<unknown>") -> List[RawFinding]:
        """Scan code for SSTI vulnerabilities."""
        findings: List[RawFinding] = []
        
        try:
            tree = ast.parse(code)
        except SyntaxError:
            return findings
        
        # Track template imports and variable assignments
        template_vars = self._find_template_variables(tree, code)
        
        # Find render calls with user input
        findings.extend(self._check_jinja2_render(tree, code, filepath, template_vars))
        findings.extend(self._check_mako_render(tree, code, filepath, template_vars))
        findings.extend(self._check_string_template(tree, code, filepath, template_vars))
        findings.extend(self._check_tornado_render(tree, code, filepath, template_vars))
        
        return findings
    
    def _find_template_variables(self, tree: ast.AST, code: str) -> dict:
        """Find variables that hold template objects."""
        template_vars = {}
        
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        var_name = target.id
                        # Check if value is a template instantiation
                        if self._is_template_creation(node.value, code):
                            template_vars[var_name] = self._get_template_type(node.value, code)
        
        return template_vars
    
    def _is_template_creation(self, node: ast.AST, code: str) -> bool:
        """Check if a node creates a template object."""
        if isinstance(node, ast.Call):
            call_str = ast.unparse(node) if hasattr(ast, 'unparse') else self._node_to_string(node, code)
            
            for engine, patterns in self.TEMPLATE_PATTERNS.items():
                for import_name in patterns['imports']:
                    if import_name in call_str:
                        return True
        
        return False
    
    def _get_template_type(self, node: ast.AST, code: str) -> str:
        """Determine the template engine type."""
        call_str = ast.unparse(node) if hasattr(ast, 'unparse') else self._node_to_string(node, code)
        
        for engine, patterns in self.TEMPLATE_PATTERNS.items():
            for import_name in patterns['imports']:
                if import_name in call_str:
                    return engine
        
        return "unknown"
    
    def _check_jinja2_render(self, tree: ast.AST, code: str, filepath: str, template_vars: dict) -> List[RawFinding]:
        """Check for Jinja2 template injection."""
        findings = []
        lines = code.split('\n')
        
        # Pattern 1: Find lines with Template() and user input
        for i, line in enumerate(lines):
            if 'Template' in line and ('jinja2' in code.lower() or 'from_string' in line):
                # Check if this line or nearby lines have user input
                context = '\n'.join(lines[max(0, i-3):min(len(lines), i+4)])
                if self._context_has_user_input(context):
                    findings.append(RawFinding(
                        rule_id="PY_SSTI_001",
                        type="Server-Side Template Injection (SSTI)",
                        cwe="CWE-1336",
                        severity="ERROR",
                        confidence="high",
                        file_path=filepath,
                        start_line=i + 1,
                        message="Jinja2 template rendered with user-controlled input",
                        engine="python",
                        evidence={
                            "matched_line": line.strip(),
                            "engine": "jinja2",
                        }
                    ))
            
            # Pattern 2: from_string with user input
            if 'from_string' in line:
                context = '\n'.join(lines[max(0, i-3):min(len(lines), i+4)])
                if self._context_has_user_input(context):
                    findings.append(RawFinding(
                        rule_id="PY_SSTI_002",
                        type="Server-Side Template Injection (SSTI)",
                        cwe="CWE-1336",
                        severity="ERROR",
                        confidence="high",
                        file_path=filepath,
                        start_line=i + 1,
                        message="Jinja2 from_string() with user-controlled template",
                        engine="python",
                        evidence={
                            "matched_line": line.strip(),
                            "engine": "jinja2",
                        }
                    ))
        
        return findings
    
    def _check_mako_render(self, tree: ast.AST, code: str, filepath: str, template_vars: dict) -> List[RawFinding]:
        """Check for Mako template injection."""
        findings = []
        lines = code.split('\n')
        
        for i, line in enumerate(lines):
            if 'mako' in line.lower() and 'Template' in line:
                context = '\n'.join(lines[max(0, i-3):min(len(lines), i+4)])
                if self._context_has_user_input(context):
                    findings.append(RawFinding(
                        rule_id="PY_SSTI_003",
                        type="Server-Side Template Injection (SSTI)",
                        cwe="CWE-1336",
                        severity="ERROR",
                        confidence="high",
                        file_path=filepath,
                        start_line=i + 1,
                        message="Mako template rendered with user-controlled input",
                        engine="python",
                        evidence={
                            "matched_line": line.strip(),
                            "engine": "mako",
                        }
                    ))
        
        return findings
    
    def _check_string_template(self, tree: ast.AST, code: str, filepath: str, template_vars: dict) -> List[RawFinding]:
        """Check for string.Template injection."""
        findings = []
        lines = code.split('\n')
        
        # Pattern 1: string.Template(user_input) in same line
        for i, line in enumerate(lines):
            if 'Template' in line and 'string' in code.lower():
                context = '\n'.join(lines[max(0, i-5):min(len(lines), i+4)])
                if self._context_has_user_input(context):
                    findings.append(RawFinding(
                        rule_id="PY_SSTI_004",
                        type="Server-Side Template Injection (SSTI)",
                        cwe="CWE-1336",
                        severity="WARN",
                        confidence="medium",
                        file_path=filepath,
                        start_line=i + 1,
                        message="string.Template with user-controlled template",
                        engine="python",
                        evidence={
                            "matched_line": line.strip(),
                            "engine": "string",
                        }
                    ))
        
        return findings
    
    def _check_tornado_render(self, tree: ast.AST, code: str, filepath: str, template_vars: dict) -> List[RawFinding]:
        """Check for Tornado template injection."""
        findings = []
        lines = code.split('\n')
        
        for i, line in enumerate(lines):
            if 'tornado' in line.lower() and 'Template' in line:
                context = '\n'.join(lines[max(0, i-3):min(len(lines), i+4)])
                if self._context_has_user_input(context):
                    findings.append(RawFinding(
                        rule_id="PY_SSTI_005",
                        type="Server-Side Template Injection (SSTI)",
                        cwe="CWE-1336",
                        severity="ERROR",
                        confidence="high",
                        file_path=filepath,
                        start_line=i + 1,
                        message="Tornado template rendered with user-controlled input",
                        engine="python",
                        evidence={
                            "matched_line": line.strip(),
                            "engine": "tornado",
                        }
                    ))
        
        return findings
    
    def _context_has_user_input(self, context: str) -> bool:
        """Check if context contains user input patterns."""
        for pattern in self.USER_INPUT_PATTERNS:
            if re.search(pattern, context, re.IGNORECASE):
                return True
        return False
    
    def _node_to_string(self, node: ast.AST, code: str) -> str:
        """Convert AST node to string (fallback for Python < 3.9)."""
        try:
            lines = code.split('\n')
            if hasattr(node, 'lineno') and hasattr(node, 'end_lineno'):
                start_line = node.lineno - 1
                end_line = node.end_lineno if node.end_lineno else node.lineno
                return '\n'.join(lines[start_line:end_line])
        except:
            pass
        return ""


def analyze_code_unit(code_unit: CodeUnit) -> List[RawFinding]:
    """Analyze a CodeUnit for SSTI vulnerabilities."""
    if code_unit.language != "python":
        return []
    
    engine = SSTIEngine()
    return engine.scan_code(code_unit.content, code_unit.path)
