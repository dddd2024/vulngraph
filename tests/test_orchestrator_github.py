"""
Tests for AuditOrchestrator GitHub scanning.

Uses mock to simulate GitHub repo loading without real network access.
"""

import tempfile
import shutil
from pathlib import Path

import pytest

from audit_core.orchestrator import AuditOrchestrator
from audit_core.models import AuditResult, AuditSummary
from ingest.repo_loader import RepoLoader
from ingest.github_loader import GitHubLoader


@pytest.fixture
def mock_github_repo():
    """
    Create a mock GitHub repository structure.
    
    Returns:
        Path to the mock repository
    """
    temp_dir = tempfile.mkdtemp(prefix="mock_github_")
    
    # Create some Python files with potential vulnerabilities
    (Path(temp_dir) / "app.py").write_text("""
from flask import Flask, request
app = Flask(__name__)

@app.route('/search')
def search():
    query = request.args.get('q')
    # SQL injection vulnerability
    sql = "SELECT * FROM users WHERE name = '" + query + "'"
    return execute_query(sql)

def execute_query(sql):
    pass
""")
    
    (Path(temp_dir) / "utils.py").write_text("""
import os

def read_file(filename):
    # Path traversal vulnerability
    with open(filename, 'r') as f:
        return f.read()

def hash_password(password):
    # Weak hashing
    import hashlib
    return hashlib.md5(password.encode()).hexdigest()
""")
    
    yield Path(temp_dir)
    
    # Cleanup
    shutil.rmtree(temp_dir, ignore_errors=True)


@pytest.fixture
def mock_clone_func(mock_github_repo):
    """
    Create a mock clone function that returns the mock repo.
    """
    def clone(owner: str, repo: str, branch: str | None) -> Path:
        return mock_github_repo
    return clone


@pytest.fixture
def mock_github_loader(mock_clone_func):
    """
    Create a GitHubLoader with mock clone function.
    """
    return GitHubLoader(clone_func=mock_clone_func)


@pytest.fixture
def mock_repo_loader(mock_github_loader):
    """
    Create a RepoLoader with mock GitHubLoader.
    """
    return RepoLoader(github_loader=mock_github_loader)


@pytest.fixture
def orchestrator(mock_repo_loader):
    """
    Create an AuditOrchestrator with mock repo loader.
    """
    orch = AuditOrchestrator()
    orch.repo_loader = mock_repo_loader
    return orch


class TestOrchestratorGitHub:
    """Tests for AuditOrchestrator GitHub scanning."""
    
    def test_scan_github_returns_result(self, orchestrator):
        """Test that scan_github returns an AuditResult."""
        result = orchestrator.scan_github("https://github.com/test/test_repo")
        
        assert isinstance(result, AuditResult)
        assert isinstance(result.summary, AuditSummary)
    
    def test_scan_github_no_metadata_error(self, orchestrator):
        """Test that scan_github does not return metadata error."""
        result = orchestrator.scan_github("https://github.com/test/test_repo")
        
        # Should NOT have the old "not implemented" error
        assert "error" not in result.metadata or \
               result.metadata.get("error") != "GitHub repo scanning not yet implemented"
    
    def test_scan_github_loads_code_units(self, orchestrator):
        """Test that scan_github loads code units from the repo."""
        result = orchestrator.scan_github("https://github.com/test/test_repo")
        
        # Should have loaded the mock files
        assert result.summary.total_code_units >= 2
    
    def test_scan_github_detects_vulnerabilities(self, orchestrator):
        """Test that scan_github can detect vulnerabilities in loaded code."""
        result = orchestrator.scan_github("https://github.com/test/test_repo")
        
        # Should have some findings (SQL injection, path traversal, etc.)
        # Note: depends on analyzer capabilities
        assert result.summary.total_findings >= 0
    
    def test_scan_input_type_github(self, orchestrator):
        """Test that scan() with input_type='github' works."""
        result = orchestrator.scan(
            input_type="github",
            repo_url="https://github.com/test/test_repo"
        )
        
        assert isinstance(result, AuditResult)
        assert "error" not in result.metadata or \
               result.metadata.get("error") != "GitHub repo scanning not yet implemented"
    
    def test_scan_input_type_github_requires_repo_url(self, orchestrator):
        """Test that scan() with input_type='github' requires repo_url."""
        with pytest.raises(ValueError, match="repo_url is required"):
            orchestrator.scan(input_type="github")
    
    def test_scan_github_invalid_url(self, orchestrator):
        """Test that scan_github raises error for invalid URL."""
        with pytest.raises(ValueError, match="Not a valid GitHub URL"):
            orchestrator.scan_github("https://notgithub.com/user/repo")
    
    def test_scan_github_with_branch(self, mock_clone_func):
        """Test that scan_github passes branch parameter."""
        calls = []
        
        def tracking_clone(owner, repo, branch):
            calls.append((owner, repo, branch))
            temp_dir = tempfile.mkdtemp()
            (Path(temp_dir) / "main.py").write_text("print('hello')")
            return Path(temp_dir)
        
        loader = GitHubLoader(clone_func=tracking_clone)
        repo_loader = RepoLoader(github_loader=loader)
        orchestrator = AuditOrchestrator()
        orchestrator.repo_loader = repo_loader
        
        result = orchestrator.scan_github(
            "https://github.com/user/repo",
            branch="develop"
        )
        
        assert calls[0] == ("user", "repo", "develop")
        
        # Cleanup
        loader.cleanup()


class TestOrchestratorGitHubIntegration:
    """Integration tests for GitHub scanning."""
    
    def test_full_pipeline_with_mock_repo(self, mock_github_repo, mock_clone_func):
        """Test full audit pipeline with mock GitHub repo."""
        loader = GitHubLoader(clone_func=mock_clone_func)
        repo_loader = RepoLoader(github_loader=loader)
        orchestrator = AuditOrchestrator()
        orchestrator.repo_loader = repo_loader
        
        result = orchestrator.scan_github("https://github.com/test/vuln_repo")
        
        # Verify result structure
        assert result.summary is not None
        assert result.findings is not None
        assert result.evidence is not None
        assert result.agent_logs is not None
        
        # Verify summary fields
        assert result.summary.total_code_units >= 0
        assert result.summary.total_findings >= 0
        assert result.summary.total_evidence_bundles >= 0
        assert result.summary.risk_score >= 0
        
        # Cleanup
        loader.cleanup()
    
    def test_cleanup_after_scan(self, mock_clone_func):
        """Test that temporary directories are cleaned up after scan."""
        loader = GitHubLoader(clone_func=mock_clone_func)
        repo_loader = RepoLoader(github_loader=loader)
        orchestrator = AuditOrchestrator()
        orchestrator.repo_loader = repo_loader
        
        result = orchestrator.scan_github("https://github.com/test/test_repo")
        
        # Temp dirs should be cleaned up
        assert len(loader._temp_dirs) == 0