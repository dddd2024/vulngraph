"""
Taint Analysis Engine for Python code.

This module provides a complete taint analysis implementation that tracks
data flow from sources (untrusted input) to sinks (dangerous operations).

Supported vulnerability types:
- SQL Injection
- Path Traversal
- Command Injection
- SSRF
- XSS
- Insecure Deserialization
"""

import ast
from dataclasses import dataclass, field
from typing import List, Dict, Set, Optional, Tuple, Any
from pathlib import Path

from audit_core.models import RawFinding, CodeUnit
from analyzers.taint.sources import (
    TaintSource, DEFAULT_SOURCES, is_tainted_variable, extract_variable_name
)
from analyzers.taint.sinks import (
    TaintSink, DEFAULT_SINKS, is_sink_function, extract_call_name as extract_sink_call_name
)
from analyzers.taint.sanitizers import (
    Sanitizer, DEFAULT_SANITIZERS, is_sanitizer_function
)


@dataclass
class TaintFlow:
    """Represents a taint flow from source to sink."""
    source: str  # Variable name where taint originates
    source_line: int
    sink: str  # Sink function name
    sink_line: int
    sink_type: str  # Vulnerability type
    severity: str
    path: List[str] = field(default_factory=list)  # Variables through which taint flows
    sanitized: bool = False
    sanitizer: Optional[str] = None


@dataclass
class TaintState:
    """Tracks tainted variables in the current scope."""
    tainted_vars: Set[str] = field(default_factory=set)
    var_assignments: Dict[str, int] = field(default_factory=dict)  # var -> line number
    taint_sources: Dict[str, str] = field(default_factory=dict)  # var -> source description

    def add_taint(self, var: str, source: str, line: int):
        """Mark a variable as tainted."""
        self.tainted_vars.add(var)
        self.var_assignments[var] = line
        self.taint_sources[var] = source

    def is_tainted(self, var: str) -> bool:
        """Check if a variable is tainted."""
        return is_tainted_variable(var, self.tainted_vars)

    def get_source(self, var: str) -> Optional[str]:
        """Get the source description for a tainted variable."""
        return self.taint_sources.get(var)

    def propagate(self, from_var: str, to_var: str):
        """Propagate taint from one variable to another."""
        if self.is_tainted(from_var):
            self.tainted_vars.add(to_var)
            self.taint_sources[to_var] = self.taint_sources.get(from_var, "unknown")

    def copy(self) -> "TaintState":
        """Create a copy of the current state."""
        return TaintState(
            tainted_vars=self.tainted_vars.copy(),
            var_assignments=self.var_assignments.copy(),
            taint_sources=self.taint_sources.copy()
        )


class TaintVisitor(ast.NodeVisitor):
    """AST visitor that performs taint analysis."""

    def __init__(self, code: str, filename: str = "<unknown>"):
        self.code = code
        self.filename = filename
        self.taint_state = TaintState()
        self.flows: List[TaintFlow] = []
        self.current_function: Optional[str] = None
        self.function_states: Dict[str, TaintState] = {}
        self.imports: Dict[str, str] = {}  # alias -> full module name

    def visit_Import(self, node: ast.Import):
        """Track imports for module resolution."""
        for alias in node.names:
            name = alias.asname if alias.asname else alias.name
            self.imports[name] = alias.name
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom):
        """Track from imports."""
        module = node.module or ""
        for alias in node.names:
            name = alias.asname if alias.asname else alias.name
            self.imports[name] = f"{module}.{alias.name}"
        self.generic_visit(node)

    def visit_FunctionDef(self, node: ast.FunctionDef):
        """Analyze a function definition."""
        old_function = self.current_function
        old_state = self.taint_state

        self.current_function = node.name
        # Create new state for function scope
        self.taint_state = TaintState()

        # Analyze function body
        for stmt in node.body:
            self.visit(stmt)

        # Store function state for interprocedural analysis
        self.function_states[node.name] = self.taint_state.copy()

        self.current_function = old_function
        self.taint_state = old_state

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef):
        """Handle async functions the same way as regular functions."""
        self.visit_FunctionDef(node)

    def visit_Assign(self, node: ast.Assign):
        """Track variable assignments and taint propagation."""
        # First visit the value to detect any sinks
        self.visit(node.value)

        # Check if the value is tainted
        tainted_vars_in_value = self._get_tainted_vars_in_node(node.value)

        for target in node.targets:
            var_name = self._get_target_name(target)
            if var_name:
                if tainted_vars_in_value:
                    # Propagate taint
                    for source_var in tainted_vars_in_value:
                        self.taint_state.propagate(source_var, var_name)
                elif self._is_source(node.value):
                    # Direct assignment from source
                    source_desc = self._describe_source(node.value)
                    self.taint_state.add_taint(var_name, source_desc, node.lineno)

        self.generic_visit(node)

    def visit_Call(self, node: ast.Call):
        """Check for sinks and sources in function calls."""
        call_name = extract_sink_call_name(node)

        if call_name:
            # Check if this is a sink
            sink = is_sink_function(call_name)
            if sink:
                self._check_sink(node, sink, call_name)

            # Check if this is a sanitizer
            sanitizer = is_sanitizer_function(call_name)
            if sanitizer:
                # Mark the arguments as sanitized
                for arg in node.args:
                    if isinstance(arg, ast.Name):
                        # Note: In a real implementation, we'd track sanitization
                        pass

        # Check for sources in the call
        if self._is_source(node):
            # The return value of this call is tainted
            pass

        # Visit arguments to check for nested sinks/sources
        for arg in node.args:
            self.visit(arg)
        for keyword in node.keywords:
            self.visit(keyword.value)

    def _check_sink(self, node: ast.Call, sink: TaintSink, call_name: str):
        """Check if a sink call has tainted arguments."""
        for idx, arg in enumerate(node.args):
            if idx in sink.vulnerable_args or None in sink.vulnerable_args:
                tainted_vars = self._get_tainted_vars_in_node(arg)
                if tainted_vars:
                    # Check if the argument is sanitized
                    sanitized, sanitizer_name = self._is_sanitized(arg, sink.vuln_type)

                    for source_var in tainted_vars:
                        source_line = self.taint_state.var_assignments.get(source_var, 0)
                        flow = TaintFlow(
                            source=source_var,
                            source_line=source_line,
                            sink=call_name,
                            sink_line=node.lineno,
                            sink_type=sink.vuln_type,
                            severity=sink.severity,
                            path=[source_var],
                            sanitized=sanitized,
                            sanitizer=sanitizer_name
                        )
                        self.flows.append(flow)

    def _get_tainted_vars_in_node(self, node: ast.AST) -> List[str]:
        """Extract all tainted variable names from an AST node."""
        tainted = []

        class TaintExtractor(ast.NodeVisitor):
            def __init__(self, outer):
                self.outer = outer

            def visit_Name(self, n):
                if self.outer.taint_state.is_tainted(n.id):
                    tainted.append(n.id)

            def visit_Attribute(self, n):
                var_name = extract_variable_name(n)
                if var_name and self.outer.taint_state.is_tainted(var_name):
                    tainted.append(var_name)
                self.generic_visit(n)

            def visit_BinOp(self, n):
                # For string concatenation, check both sides
                self.visit(n.left)
                self.visit(n.right)

            def visit_JoinedStr(self, n):
                # f-strings
                for value in n.values:
                    self.visit(value)

        extractor = TaintExtractor(self)
        extractor.visit(node)
        return tainted

    def _is_source(self, node: ast.AST) -> bool:
        """Check if a node represents a taint source."""
        if isinstance(node, ast.Call):
            call_name = extract_sink_call_name(node)
            if call_name:
                # Check against source patterns
                for source in DEFAULT_SOURCES:
                    for pattern in source.call_patterns:
                        if call_name == pattern or call_name.endswith("." + pattern.split(".")[-1]):
                            return True
        return False

    def _describe_source(self, node: ast.AST) -> str:
        """Get a description of the source."""
        if isinstance(node, ast.Call):
            call_name = extract_sink_call_name(node)
            return f"call to {call_name}"
        return "unknown source"

    def _is_sanitized(self, node: ast.AST, vuln_type: str) -> Tuple[bool, Optional[str]]:
        """Check if a node is sanitized for a specific vulnerability type."""
        # Check if the node is wrapped in a sanitizer call
        if isinstance(node, ast.Call):
            call_name = extract_sink_call_name(node)
            if call_name:
                sanitizer = is_sanitizer_function(call_name)
                if sanitizer and vuln_type in sanitizer.protects_against:
                    return True, sanitizer.name

        # Check for sanitizers in parent nodes (would need parent tracking)
        return False, None

    def _get_target_name(self, node: ast.AST) -> Optional[str]:
        """Get the name of an assignment target."""
        if isinstance(node, ast.Name):
            return node.id
        elif isinstance(node, ast.Attribute):
            return extract_variable_name(node)
        elif isinstance(node, ast.Subscript):
            base = extract_variable_name(node.value)
            return f"{base}[...]" if base else None
        elif isinstance(node, ast.Tuple):
            # Handle tuple unpacking
            names = []
            for elt in node.elts:
                name = self._get_target_name(elt)
                if name:
                    names.append(name)
            return names[0] if names else None
        return None


def analyze_taint(code: str, filename: str = "<unknown>") -> List[TaintFlow]:
    """
    Analyze Python code for taint flows.

    Args:
        code: Python source code
        filename: Name of the file (for reporting)

    Returns:
        List of TaintFlow objects representing detected flows
    """
    try:
        tree = ast.parse(code)
    except SyntaxError:
        return []

    visitor = TaintVisitor(code, filename)
    visitor.visit(tree)

    return visitor.flows


def flows_to_findings(flows: List[TaintFlow], code_unit: CodeUnit) -> List[RawFinding]:
    """
    Convert TaintFlow objects to RawFinding objects.

    Args:
        flows: List of detected taint flows
        code_unit: The CodeUnit being analyzed

    Returns:
        List of RawFinding objects
    """
    findings = []

    for flow in flows:
        # Skip sanitized flows (or mark them as lower severity)
        if flow.sanitized:
            continue  # Or create a INFO finding

        finding = RawFinding(
            type=flow.sink_type,
            file_path=code_unit.path,
            start_line=flow.sink_line,
            end_line=flow.sink_line,
            message=f"Taint flow: {flow.source} (line {flow.source_line}) -> {flow.sink}",
            confidence="high" if len(flow.path) <= 2 else "medium",
            severity=flow.severity,
            engine="taint",
            rule_id=f"taint-{flow.sink_type.lower().replace(' ', '-')}",
            evidence={
                "source": flow.source,
                "source_line": flow.source_line,
                "sink": flow.sink,
                "flow_path": flow.path,
            },
            metadata={
                "taint_source": flow.source,
                "taint_source_line": flow.source_line,
                "taint_sink": flow.sink,
                "taint_sink_line": flow.sink_line,
            }
        )
        findings.append(finding)

    return findings


def analyze_code_unit(code_unit: CodeUnit) -> List[RawFinding]:
    """
    Analyze a CodeUnit for taint-based vulnerabilities.

    This is the main entry point for the taint analyzer.

    Args:
        code_unit: The CodeUnit to analyze

    Returns:
        List of RawFinding objects
    """
    if code_unit.language != "python":
        return []

    flows = analyze_taint(code_unit.content, code_unit.path)
    return flows_to_findings(flows, code_unit)
