"""
Audit orchestrator - main entry point for the audit pipeline.

The AuditOrchestrator coordinates the entire audit process:
1. Load code units from various sources
2. Run analyzers to detect vulnerabilities
3. Merge and deduplicate findings
4. Run agents to analyze findings
5. Build evidence bundles
6. Generate final audit result
"""

from audit_core.models import (
    CodeUnit, RawFinding, AgentHypothesis, AgentLog,
    JudgeDecision, EvidenceBundle, AuditSummary, AuditResult
)
from audit_core.registry import AnalyzerRegistry, build_default_registry
from audit_core.result_merger import merge_findings
from ingest.repo_loader import RepoLoader
from agents.recon_agent import ReconAgent
from agents.analysis_agent import AnalysisAgent
from agents.judge_agent import JudgeAgent
from evidence.evidence_builder import build_evidence_bundle


class AuditOrchestrator:
    """
    Main orchestrator for the audit pipeline.
    
    This is the primary entry point for new audit workflows.
    It coordinates all components to perform a complete security audit.
    """
    
    def __init__(self, registry: AnalyzerRegistry | None = None):
        """
        Initialize the orchestrator.
        
        Args:
            registry: Optional analyzer registry (defaults to build_default_registry)
        """
        self.registry = registry or build_default_registry()
        self.repo_loader = RepoLoader()
        self.recon_agent = ReconAgent()
        self.analysis_agent = AnalysisAgent()
        self.judge_agent = JudgeAgent()
    
    def scan_code(self, code: str, language: str | None = None) -> AuditResult:
        """
        Scan a code snippet.
        
        Args:
            code: The code snippet to scan
            language: Optional language hint
            
        Returns:
            AuditResult with findings and evidence
        """
        code_units = self.repo_loader.load_code_snippet(code, language)
        return self._run_audit(code_units)
    
    def scan_path(self, repo_path: str) -> AuditResult:
        """
        Scan a local repository path.
        
        Args:
            repo_path: Path to the repository
            
        Returns:
            AuditResult with findings and evidence
        """
        code_units = self.repo_loader.load_local_repo(repo_path)
        return self._run_audit(code_units)
    
    def scan(
        self,
        *,
        input_type: str,
        code: str | None = None,
        repo_path: str | None = None,
        repo_url: str | None = None,
        language: str | None = None
    ) -> AuditResult:
        """
        Main scan entry point.
        
        Args:
            input_type: Type of input ('code', 'path', 'github')
            code: Code snippet (for input_type='code')
            repo_path: Local repo path (for input_type='path')
            repo_url: GitHub repo URL (for input_type='github')
            language: Optional language hint
            
        Returns:
            AuditResult with findings and evidence
        """
        if input_type == "code":
            if code is None:
                raise ValueError("code is required for input_type='code'")
            return self.scan_code(code, language)
        
        elif input_type == "path":
            if repo_path is None:
                raise ValueError("repo_path is required for input_type='path'")
            return self.scan_path(repo_path)
        
        elif input_type == "github":
            # TODO: Implement GitHub repo scanning
            # For now, return empty result
            return AuditResult(
                summary=AuditSummary(),
                metadata={"error": "GitHub repo scanning not yet implemented"}
            )
        
        else:
            raise ValueError(f"Unknown input_type: {input_type}")
    
    def _run_audit(self, code_units: list[CodeUnit]) -> AuditResult:
        """
        Run the full audit pipeline.
        
        Args:
            code_units: List of code units to analyze
            
        Returns:
            Complete AuditResult
        """
        # Step 1: Run recon agent
        recon_hypotheses, recon_logs = self.recon_agent.run(code_units)
        
        # Step 2: Run analyzers
        all_findings: list[RawFinding] = []
        for analyzer in self.registry.get_analyzers():
            findings = analyzer.analyze(code_units)
            all_findings.extend(findings)
        
        # Step 3: Merge findings
        merged_findings = merge_findings(all_findings)
        
        # Step 4: Process each finding with agents
        evidence_bundles: list[EvidenceBundle] = []
        all_agent_logs: list[AgentLog] = recon_logs.copy()
        
        for finding in merged_findings:
            # Find corresponding code unit
            code_unit = self._find_code_unit(code_units, finding.file_path)
            
            # Run analysis agent
            hypothesis, analysis_log = self.analysis_agent.run(finding, code_unit)
            all_agent_logs.append(analysis_log)
            
            # Run judge agent
            judge_decision, judge_log = self.judge_agent.run(
                finding, [hypothesis], None
            )
            all_agent_logs.append(judge_log)
            
            # Build evidence bundle
            evidence = build_evidence_bundle(
                finding=finding,
                code_unit=code_unit,
                hypotheses=[hypothesis],
                agent_logs=[analysis_log, judge_log],
                judge_decision=judge_decision
            )
            evidence_bundles.append(evidence)
        
        # Step 5: Generate summary
        languages = list(set(u.language for u in code_units if u.language != "unknown"))
        scanned_files = [u.path for u in code_units]
        
        # Calculate overall risk score
        if evidence_bundles:
            risk_scores = [
                e.judge_decision.risk_score if e.judge_decision else 0
                for e in evidence_bundles
            ]
            overall_risk = sum(risk_scores) / len(risk_scores)
        else:
            overall_risk = 0
        
        summary = AuditSummary(
            total_code_units=len(code_units),
            total_findings=len(merged_findings),
            total_evidence_bundles=len(evidence_bundles),
            risk_score=overall_risk,
            languages=languages,
            scanned_files=scanned_files
        )
        
        # Step 6: Return result
        return AuditResult(
            summary=summary,
            findings=merged_findings,
            evidence=evidence_bundles,
            agent_logs=all_agent_logs
        )
    
    def _find_code_unit(self, code_units: list[CodeUnit], file_path: str) -> CodeUnit | None:
        """
        Find a code unit by file path.
        
        Args:
            code_units: List of code units to search
            file_path: Path to find
            
        Returns:
            Matching CodeUnit or None
        """
        for unit in code_units:
            if unit.path == file_path or unit.path.endswith(file_path):
                return unit
        return None
