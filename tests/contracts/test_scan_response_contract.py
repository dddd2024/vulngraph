"""
Tests for /scan API response contract.

Verifies that /scan returns all required fields and conforms to JSON Schema.
"""

import json
import pytest
from pathlib import Path
from jsonschema import validate, ValidationError
from fastapi.testclient import TestClient

from api.server import app
from audit_core.orchestrator import AuditOrchestrator
from audit_core.models import AuditResult


client = TestClient(app)


def load_schema(schema_name: str) -> dict:
    """Load JSON Schema from contracts directory."""
    schema_path = Path(__file__).parent.parent.parent / "contracts" / schema_name
    with open(schema_path, "r", encoding="utf-8") as f:
        return json.load(f)


class TestScanResponseContract:
    """Tests for /scan response structure."""
    
    def test_scan_api_returns_valid_schema(self):
        """Test that POST /scan returns valid response conforming to JSON Schema."""
        code = '''
def get_user(user_id):
    cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
'''
        resp = client.post("/scan", json={
            "input_type": "code",
            "code": code,
            "language": "python",
        })
        assert resp.status_code == 200
        data = resp.json()
        
        # Load and validate against JSON Schema
        schema = load_schema("scan_response.schema.json")
        validate(instance=data, schema=schema)
    
    def test_scan_api_returns_summary(self):
        """Test that /scan returns summary field."""
        resp = client.post("/scan", json={
            "input_type": "code",
            "code": "def test(): pass",
            "language": "python",
        })
        assert resp.status_code == 200
        data = resp.json()
        
        assert "summary" in data
        summary = data["summary"]
        assert "total_code_units" in summary
        assert "total_findings" in summary
        assert "total_evidence_bundles" in summary
        assert "risk_score" in summary
        assert "languages" in summary
        assert "scanned_files" in summary
    
    def test_scan_api_returns_findings(self):
        """Test that /scan returns findings field."""
        resp = client.post("/scan", json={
            "input_type": "code",
            "code": "def test(): pass",
            "language": "python",
        })
        assert resp.status_code == 200
        data = resp.json()
        
        assert "findings" in data
        assert isinstance(data["findings"], list)
    
    def test_scan_api_returns_evidence(self):
        """Test that /scan returns evidence field."""
        resp = client.post("/scan", json={
            "input_type": "code",
            "code": "def test(): pass",
            "language": "python",
        })
        assert resp.status_code == 200
        data = resp.json()
        
        assert "evidence" in data
        assert isinstance(data["evidence"], list)
    
    def test_scan_api_returns_agent_logs(self):
        """Test that /scan returns agent_logs field."""
        resp = client.post("/scan", json={
            "input_type": "code",
            "code": "def test(): pass",
            "language": "python",
        })
        assert resp.status_code == 200
        data = resp.json()
        
        assert "agent_logs" in data
        assert isinstance(data["agent_logs"], list)
    
    def test_scan_api_with_vulnerability(self):
        """Test scan response with actual vulnerability."""
        code = '''
def get_user(user_id):
    cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
'''
        resp = client.post("/scan", json={
            "input_type": "code",
            "code": code,
            "language": "python",
        })
        assert resp.status_code == 200
        data = resp.json()
        
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


class TestOrchestratorResponseContract:
    """Tests for orchestrator response structure (direct call)."""
    
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


class TestScanResponseFieldTypes:
    """Tests for /scan response field types."""
    
    def test_summary_field_types(self):
        """Test that summary fields have correct types."""
        resp = client.post("/scan", json={
            "input_type": "code",
            "code": "def test(): pass",
            "language": "python",
        })
        assert resp.status_code == 200
        data = resp.json()
        summary = data["summary"]
        
        assert isinstance(summary["total_code_units"], int)
        assert isinstance(summary["total_findings"], int)
        assert isinstance(summary["total_evidence_bundles"], int)
        assert isinstance(summary["risk_score"], (int, float))
        assert isinstance(summary["languages"], list)
        assert isinstance(summary["scanned_files"], list)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
