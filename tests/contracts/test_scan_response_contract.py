"""
Tests for /scan API response contract.

Verifies that /scan returns all required fields.
"""

import pytest
from audit_core.orchestrator import AuditOrchestrator
from audit_core.models import AuditResult


class TestScanResponseContract:
    """Tests for /scan response structure."""
    
    def test_scan_returns_summary(self):
        """Test that scan returns summary field."""
        orchestrator = AuditOrchestrator()
        result = orchestrator.scan_code("def test(): pass", language="python")
        
        data = result.model_dump(mode="json")
        assert "summary" in data
        
        summary = data["summary"]
        assert "total_code_units" in summary
        assert "total_findings" in summary
        assert "total_evidence_bundles" in summary
        assert "risk_score" in summary
        assert "languages" in summary
        assert "scanned_files" in summary
    
    def test_scan_returns_findings(self):
        """Test that scan returns findings field."""
        orchestrator = AuditOrchestrator()
        result = orchestrator.scan_code("def test(): pass", language="python")
        
        data = result.model_dump(mode="json")
        assert "findings" in data
        assert isinstance(data["findings"], list)
    
    def test_scan_returns_evidence(self):
        """Test that scan returns evidence field."""
        orchestrator = AuditOrchestrator()
        result = orchestrator.scan_code("def test(): pass", language="python")
        
        data = result.model_dump(mode="json")
        assert "evidence" in data
        assert isinstance(data["evidence"], list)
    
    def test_scan_returns_agent_logs(self):
        """Test that scan returns agent_logs field."""
        orchestrator = AuditOrchestrator()
        result = orchestrator.scan_code("def test(): pass", language="python")
        
        data = result.model_dump(mode="json")
        assert "agent_logs" in data
        assert isinstance(data["agent_logs"], list)
    
    def test_scan_with_vulnerability(self):
        """Test scan response with actual vulnerability."""
        code = '''
def get_user(user_id):
    cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
'''
        orchestrator = AuditOrchestrator()
        result = orchestrator.scan_code(code, language="python")
        
        data = result.model_dump(mode="json")
        
        # Verify all required fields present
        assert "summary" in data
        assert "findings" in data
        assert "evidence" in data
        assert "agent_logs" in data
        
        # Verify summary fields
        summary = data["summary"]
        assert summary["total_code_units"] == 1
        assert summary["total_findings"] >= 0
        assert summary["total_evidence_bundles"] >= 0
        assert isinstance(summary["risk_score"], (int, float))
        assert isinstance(summary["languages"], list)
        assert isinstance(summary["scanned_files"], list)


class TestScanResponseFieldTypes:
    """Tests for /scan response field types."""
    
    def test_summary_field_types(self):
        """Test that summary fields have correct types."""
        orchestrator = AuditOrchestrator()
        result = orchestrator.scan_code("def test(): pass", language="python")
        
        data = result.model_dump(mode="json")
        summary = data["summary"]
        
        assert isinstance(summary["total_code_units"], int)
        assert isinstance(summary["total_findings"], int)
        assert isinstance(summary["total_evidence_bundles"], int)
        assert isinstance(summary["risk_score"], (int, float))
        assert isinstance(summary["languages"], list)
        assert isinstance(summary["scanned_files"], list)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
