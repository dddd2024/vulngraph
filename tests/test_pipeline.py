from pathlib import Path

from detector.vuln_detector import detect_all
from parser.call_graph import build_call_graph


def test_demo_repo_contains_expected_vulns():
    findings = detect_all("repo")
    types = {f["type"] for f in findings}
    assert "SQL Injection" in types
    assert "Path Traversal" in types
    assert "Privilege Escalation" in types


def test_call_graph_builds_edges():
    g = build_call_graph("repo")
    assert "search_api" in g.nodes
    assert "search_user" in g.nodes
    assert ("search_api", "search_user") in g.edges

