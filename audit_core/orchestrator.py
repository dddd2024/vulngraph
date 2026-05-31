"""
Audit orchestrator - main entry point for the audit pipeline.

The AuditOrchestrator coordinates the entire audit process:
1. Load code units from various sources
2. Run analyzers to detect vulnerabilities (with language-based routing)
3. Merge and deduplicate findings
4. Run agents to analyze findings (via AgentRuntime with error isolation)
5. Build evidence bundles
6. Generate final audit result
"""

import logging
from typing import Any

from audit_core.models import (
    CodeUnit, RawFinding, AgentHypothesis, AgentLog,
    JudgeDecision, EvidenceBundle, AuditSummary, AuditResult
)
from audit_core.registry import AnalyzerRegistry, build_default_registry
from audit_core.result_merger import merge_findings
from audit_core.agent_runtime import AgentRuntime
from ingest.repo_loader import RepoLoader
from agents.registry import AgentRegistry, build_default_agent_registry


logger = logging.getLogger(__name__)


class AuditOrchestrator:
    """
    Main orchestrator for the audit pipeline.

    This is the primary entry point for new audit workflows.
    It coordinates all components to perform a complete security audit.

    Supports optional LLM integration:
    - Pass an LLMClientBase instance via llm_client parameter
    - Or pass a dict config via llm_config to auto-create a client
    - If neither is provided, agents use rule-based fallback (no API key needed)

    Error Isolation:
    - Uses AgentRuntime to wrap Agent calls with try/except
    - Agent failures are logged and don't crash the entire scan
    - Fallback outputs are generated for failed Agents

    Analyzer Routing:
    - Analyzers are routed by CodeUnit.language
    - Each analyzer only receives code_units of supported languages
    - Unknown language code_units are skipped (no analyzer runs on them)
    - Analyzer failures are logged but don't crash the scan
    """

    def __init__(
        self,
        registry: AnalyzerRegistry | None = None,
        agent_registry: AgentRegistry | None = None,
        *,
        llm_client: Any | None = None,
        llm_config: dict[str, Any] | None = None,
    ):
        """
        Initialize the orchestrator.

        Args:
            registry: Optional analyzer registry (defaults to build_default_registry)
            agent_registry: Optional agent registry (defaults to build_default_agent_registry)
            llm_client: Optional LLMClientBase instance for LLM-powered analysis.
                        When provided, AnalysisAgent will use this client instead
                        of rule-based fallback.
            llm_config: Optional dict for creating an LLM client via factory.
                        Example: {"provider": "mock"} or {"provider": "openai", "api_key": "..."}
                        Ignored if llm_client is directly provided.
        """
        self.registry = registry or build_default_registry()
        self.repo_loader = RepoLoader()

        # Resolve agent registry and obtain agents from it
        self.agent_registry = agent_registry or build_default_agent_registry()
        self.recon_agent = self.agent_registry.get_recon()
        self.judge_agent = self.agent_registry.get_judge()

        # Initialize AgentRuntime for error-isolated execution
        self.agent_runtime = AgentRuntime()

        # Resolve LLM client
        resolved_client = self._resolve_llm_client(llm_client, llm_config)
        self.analysis_agent = self.agent_registry.get_analysis()
        if self.analysis_agent is not None and hasattr(self.analysis_agent, 'set_llm_client'):
            self.analysis_agent.set_llm_client(resolved_client)
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
                logger.warning(
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
        if self.analysis_agent is not None and hasattr(self.analysis_agent, 'set_llm_client'):
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

    def _group_code_units_by_language(
        self,
        code_units: list[CodeUnit]
    ) -> dict[str, list[CodeUnit]]:
        """
        Group code units by their language.

        Args:
            code_units: List of code units to group

        Returns:
            Dictionary mapping language to list of code units
        """
        groups: dict[str, list[CodeUnit]] = {}

        for unit in code_units:
            language = unit.language.lower() if unit.language else "unknown"

            if language not in groups:
                groups[language] = []
            groups[language].append(unit)

        return groups

    def _run_analyzers(
        self,
        code_units: list[CodeUnit]
    ) -> tuple[list[RawFinding], dict[str, Any]]:
        """
        Run analyzers with language-based routing and error isolation.

        This method:
        1. Groups code_units by language
        2. For each language, gets appropriate analyzers
        3. Runs each analyzer only on code_units of supported languages
        4. Handles analyzer exceptions gracefully
        5. Records analyzer errors in metadata

        Args:
            code_units: List of code units to analyze

        Returns:
            Tuple of (findings, analyzer_metadata)
            - findings: List of all RawFinding objects
            - analyzer_metadata: Dict with analyzer execution info and errors
        """
        all_findings: list[RawFinding] = []
        analyzer_metadata: dict[str, Any] = {
            "analyzer_runs": [],
            "analyzer_errors": [],
            "skipped_languages": [],
        }

        # Group code units by language
        language_groups = self._group_code_units_by_language(code_units)

        # Process each language group
        for language, units in language_groups.items():
            # Skip unknown language - no analyzer should run on it
            if language == "unknown":
                logger.warning(
                    "Skipping %d code units with unknown language. "
                    "No analyzers will run on these.",
                    len(units)
                )
                analyzer_metadata["skipped_languages"].append({
                    "language": "unknown",
                    "code_unit_count": len(units),
                    "reason": "No analyzer supports 'unknown' language"
                })
                continue

            # Get analyzers for this language
            analyzers = self.registry.get_analyzers_for_language(language)

            if not analyzers:
                logger.warning(
                    "No analyzers found for language '%s'. "
                    "Skipping %d code units.",
                    language, len(units)
                )
                analyzer_metadata["skipped_languages"].append({
                    "language": language,
                    "code_unit_count": len(units),
                    "reason": "No registered analyzer supports this language"
                })
                continue

            # Run each analyzer on the language-specific code units
            for analyzer in analyzers:
                analyzer_run_info = {
                    "analyzer_name": analyzer.name,
                    "language": language,
                    "code_unit_count": len(units),
                    "success": True,
                    "finding_count": 0,
                }

                try:
                    findings = analyzer.analyze(units)
                    all_findings.extend(findings)
                    analyzer_run_info["finding_count"] = len(findings)

                except Exception as exc:
                    # Analyzer failed - log and continue
                    analyzer_run_info["success"] = False
                    analyzer_run_info["error_type"] = type(exc).__name__
                    analyzer_run_info["error_message"] = str(exc)

                    analyzer_metadata["analyzer_errors"].append({
                        "analyzer_name": analyzer.name,
                        "language": language,
                        "error_type": type(exc).__name__,
                        "error_message": str(exc),
                        "code_unit_count": len(units),
                    })

                    logger.warning(
                        "Analyzer '%s' failed for language '%s': %s. "
                        "Continuing with other analyzers.",
                        analyzer.name, language, exc
                    )

                analyzer_metadata["analyzer_runs"].append(analyzer_run_info)

        return all_findings, analyzer_metadata

    def _run_audit(self, code_units: list[CodeUnit]) -> AuditResult:
        """
        Run the full audit pipeline with error-isolated Agent execution.

        Args:
            code_units: List of code units to analyze

        Returns:
            Complete AuditResult
        """
        all_agent_logs: list[AgentLog] = []

        # Step 1: Run recon agent via AgentRuntime (with error isolation)
        recon_result = self.agent_runtime.run_recon(self.recon_agent, code_units)
        recon_hypotheses: list[AgentHypothesis] = (
            recon_result.output if isinstance(recon_result.output, list) else []
        )
        all_agent_logs.extend(recon_result.logs)

        # Step 2: Run analyzers with language-based routing
        all_findings, analyzer_metadata = self._run_analyzers(code_units)

        # Step 3: Merge findings
        merged_findings = merge_findings(all_findings)

        # Step 4: Process each finding with agents (via AgentRuntime)
        evidence_bundles: list[EvidenceBundle] = []

        for finding in merged_findings:
            # Find corresponding code unit
            code_unit = self._find_code_unit(code_units, finding.file_path)

            # Run analysis agent via AgentRuntime (with error isolation)
            analysis_result = self.agent_runtime.run_analysis(
                self.analysis_agent, finding, code_unit
            )
            hypothesis = (
                analysis_result.output
                if isinstance(analysis_result.output, AgentHypothesis)
                else None
            )
            all_agent_logs.extend(analysis_result.logs)

            # Prepare hypotheses for judge (include recon + analysis)
            hypotheses_for_judge: list[AgentHypothesis] = []
            # Add recon hypotheses that might be related to this finding
            for h in recon_hypotheses:
                if code_unit and code_unit.id in h.supporting_evidence_ids:
                    hypotheses_for_judge.append(h)
            # Add analysis hypothesis
            if hypothesis:
                hypotheses_for_judge.append(hypothesis)

            # Run judge agent via AgentRuntime (with error isolation)
            judge_result = self.agent_runtime.run_judge(
                self.judge_agent, finding, hypotheses_for_judge, None
            )
            judge_decision = (
                judge_result.output
                if isinstance(judge_result.output, JudgeDecision)
                else None
            )
            all_agent_logs.extend(judge_result.logs)

            # Build evidence bundle via AgentRuntime (with error isolation)
            evidence, evidence_logs = self.agent_runtime.build_evidence(
                finding=finding,
                code_unit=code_unit,
                hypotheses=hypotheses_for_judge,
                agent_logs=analysis_result.logs + judge_result.logs,
                judge_decision=judge_decision
            )
            all_agent_logs.extend(evidence_logs)

            # Only add evidence if it was successfully built
            if evidence is not None:
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

        # Step 6: Return result (include analyzer metadata)
        return AuditResult(
            summary=summary,
            findings=merged_findings,
            evidence=evidence_bundles,
            agent_logs=all_agent_logs,
            metadata={"analyzer_info": analyzer_metadata}
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