"""
Tests for data model contracts.

Verifies that core data models can be serialized to JSON.
"""

import json
import pytest
from audit_core.models import (
    CodeUnit, RawFinding, AgentHypothesis, AgentLog,
    JudgeDecision, EvidenceBundle, AuditSummary, AuditResult
)


class TestCodeUnitContract:
    """Tests for CodeUnit serialization."""
    
    def test_code_unit_serializable(self):
        """Test that CodeUnit can be serialized to JSON."""
        unit = CodeUnit(
            path="test.py",
            language="python",
            content="def hello(): pass",
            start_line=1,
            end_line=3
        )
        
        # Should not raise
        data = unit.model_dump(mode="json")
        
        # Verify structure
        assert "id" in data
        assert data["path"] == "test.py"
        assert data["language"] == "python"
        assert data["content"] == "def hello(): pass"
        assert data["start_line"] == 1
        assert data["end_line"] == 3
        
        # Should be JSON serializable
        json_str = json.dumps(data)
        assert isinstance(json_str, str)


class TestRawFindingContract:
    """Tests for RawFinding serialization."""
    
    def test_raw_finding_serializable(self):
        """Test that RawFinding can be serialized to JSON."""
        finding = RawFinding(
            rule_id="TEST_001",
            type="SQL Injection",
            severity="ERROR",
            confidence="high",
            file_path="test.py",
            start_line=10,
            message="Possible SQL injection",
            engine="pattern"
        )
        
        # Should not raise
        data = finding.model_dump(mode="json")
        
        # Verify structure
        assert "id" in data
        assert data["rule_id"] == "TEST_001"
        assert data["type"] == "SQL Injection"
        assert data["severity"] == "ERROR"
        assert data["confidence"] == "high"
        assert data["file_path"] == "test.py"
        assert data["start_line"] == 10
        assert data["message"] == "Possible SQL injection"
        assert data["engine"] == "pattern"
        
        # Should be JSON serializable
        json_str = json.dumps(data)
        assert isinstance(json_str, str)


class TestEvidenceBundleContract:
    """Tests for EvidenceBundle serialization."""
    
    def test_evidence_bundle_serializable(self):
        """Test that EvidenceBundle can be serialized to JSON."""
        finding = RawFinding(
            rule_id="TEST_001",
            type="SQL Injection",
            severity="ERROR",
            confidence="high",
            file_path="test.py",
            start_line=10,
            message="Possible SQL injection",
            engine="pattern"
        )
        
        bundle = EvidenceBundle(
            finding=finding,
            snippets=[],
            agent_hypotheses=[],
            agent_logs=[]
        )
        
        # Should not raise
        data = bundle.model_dump(mode="json")
        
        # Verify structure
        assert "id" in data
        assert "finding" in data
        assert "snippets" in data
        assert "agent_hypotheses" in data
        assert "agent_logs" in data
        
        # Should be JSON serializable
        json_str = json.dumps(data)
        assert isinstance(json_str, str)


class TestAuditResultContract:
    """Tests for AuditResult serialization."""
    
    def test_audit_result_serializable(self):
        """Test that AuditResult can be serialized to JSON."""
        summary = AuditSummary(
            total_code_units=1,
            total_findings=0,
            total_evidence_bundles=0,
            risk_score=0.0,
            languages=["python"],
            scanned_files=["test.py"]
        )
        
        result = AuditResult(
            summary=summary,
            findings=[],
            evidence=[],
            agent_logs=[]
        )
        
        # Should not raise
        data = result.model_dump(mode="json")
        
        # Verify structure
        assert "summary" in data
        assert "findings" in data
        assert "evidence" in data
        assert "agent_logs" in data
        
        # Verify summary fields
        summary_data = data["summary"]
        assert summary_data["total_code_units"] == 1
        assert summary_data["total_findings"] == 0
        assert summary_data["total_evidence_bundles"] == 0
        assert summary_data["risk_score"] == 0.0
        assert summary_data["languages"] == ["python"]
        assert summary_data["scanned_files"] == ["test.py"]
        
        # Should be JSON serializable
        json_str = json.dumps(data)
        assert isinstance(json_str, str)


class TestModelRequiredFields:
    """Tests for model required fields."""
    
    def test_code_unit_required_fields(self):
        """Test that CodeUnit has all required fields."""
        unit = CodeUnit(
            path="test.py",
            language="python",
            content="def test(): pass",
            start_line=1
        )
        
        data = unit.model_dump(mode="json")
        required = ["id", "path", "language", "content", "start_line"]
        for field in required:
            assert field in data, f"Missing required field: {field}"
    
    def test_raw_finding_required_fields(self):
        """Test that RawFinding has all required fields."""
        finding = RawFinding(
            rule_id="TEST_001",
            type="SQL Injection",
            severity="ERROR",
            confidence="high",
            file_path="test.py",
            start_line=10,
            message="Test message",
            engine="pattern"
        )
        
        data = finding.model_dump(mode="json")
        required = ["id", "rule_id", "type", "severity", "confidence", 
                   "file_path", "start_line", "message", "engine"]
        for field in required:
            assert field in data, f"Missing required field: {field}"
    
    def test_audit_result_required_fields(self):
        """Test that AuditResult has all required fields."""
        summary = AuditSummary(
            total_code_units=1,
            total_findings=0,
            total_evidence_bundles=0,
            risk_score=0.0,
            languages=[],
            scanned_files=[]
        )
        
        result = AuditResult(
            summary=summary,
            findings=[],
            evidence=[],
            agent_logs=[]
        )
        
        data = result.model_dump(mode="json")
        required = ["summary", "findings", "evidence", "agent_logs"]
        for field in required:
            assert field in data, f"Missing required field: {field}"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
