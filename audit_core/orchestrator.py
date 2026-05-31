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

from typing import Any

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
    
    Supports optional LLM integration:
    - Pass an LLMClientBase instance via llm_client parameter
    - Or pass a dict config via llm_config to auto-create a client
    - If neither is provided, agents use rule-based fallback (no API key needed)
    """
    
    def __init__(
        self,
        registry: AnalyzerRegistry | None = None,
        *,
        enable_legacy: bool = False,
        llm_client: Any | None = None,
        llm_config: dict[str, Any] | None = None,
    ):
        """
        Initialize the orchestrator.
        
        Args:
            registry: Optional analyzer registry (defaults to build_default_registry)
            enable_legacy: If True, include LegacyAnalyzerAdapter in the default
                           registry.  Ignored when *registry* is explicitly provided.
            llm_client: Optional LLMClientBase instance for LLM-powered analysis.
                        When provided, AnalysisAgent will use this client instead
                        of rule-based fallback.
            llm_config: Optional dict for creating an LLM client via factory.
                        Example: {"provider": "mock"} or {"provider": "openai", "api_key": "..."}
                        Ignored if llm_client is directly provided.
        """
        self.registry = registry or build_default_registry(enable_legacy=enable_legacy)
        self.repo_loader = RepoLoader()
        self.recon_agent = ReconAgent()
        self.judge_agent = JudgeAgent()
        
        # Resolve LLM client
        resolved_client = self._resolve_llm_client(llm_client, llm_config)
        self.analysis_agent = AnalysisAgent(llm_client=resolved_client)
        self._llm_client = resolved_client
    
    @staticmethod
    def _resolve_llm_client(
        llm_client: Any | None,
        llm_config: dict[str, Any] | None,
    ) -> Any | None:
        """
        Resolve the LLM client from direct instance or config dict.
        
        Priority:
        1. Direct llm_client instance (if provided)
        2. Factory-created client from llm_config
        3. None (fallback mode)
        
        Args:
            llm_client: Direct LLMClientBase instance
            llm_config: Config dict for factory creation
            
        Returns:
            LLMClientBase instance or None
        """
        if llm_client is not None:
            return llm_client
        
        if llm_config is not None:
            try:
                from llm.base import LLMClientFactory
                provider = llm_config.get("provider", "mock")
                return LLMClientFactory.create(
                    provider=provider,
                    model=llm_config.get("model"),
                    api_key=llm_config.get("api_key"),
                    **{k: v for k, v in llm_config.items()
                       if k not in ("provider", "model", "api_key")}
                )
            except (ImportError, ValueError) as exc:
                import logging
                logging.getLogger(__name__).warning(
                    "Failed to create LLM client from config: %s. "
                    "Using fallback mode.", exc
                )
                return None
        
        return None
    
    def set_llm_client(self, client: Any) -> None:
        """
        Set or update the LLM client on the orchestrator and its agents.
        
        Args:
            client: LLMClientBase instance
        """
        self._llm_client = client
        self.analysis_agent.set_llm_client(client)
    
    def get_llm_client(self) -> Any | None:
        """
        Get the current LLM client.
        
        Returns:
            Current LLMClientBase instance or None
        """
        return self._llm_client
    
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
    
    def scan_github(self, repo_url: str, branch: str | None = None) -> AuditResult:
        """
        Scan a GitHub repository.
        
        Args:
            repo_url: GitHub repository URL
            branch: Optional branch name
            
        Returns:
            AuditResult with findings and evidence
        """
        code_units = self.repo_loader.load_github_repo(repo_url, branch)
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
            if repo_url is None:
                raise ValueError("repo_url is required for input_type='github'")
            return self.scan_github(repo_url)
        
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
