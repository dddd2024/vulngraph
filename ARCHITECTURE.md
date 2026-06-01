# VulnPatch Architecture

## Overview

VulnPatch is a modular security audit platform that combines static analysis with LLM-powered reasoning to detect and analyze vulnerabilities in source code.

**Project Positioning**: 基于多 Agent 与程序分析的应用安全审计平台

**Core Workflow**:
```
代码输入 → 项目解析 → 攻击面识别 → 静态分析/污点分析 → LLM Agent 漏洞假设 → 证据链 → Judge Agent 裁决 → 审计报告
```

---

## Primary Entry Point (唯一正式入口)

**`POST /scan`** is the **only official entry point** for the audit pipeline.

All functionality must be implemented through this entry point:

```
api/routes/scan.py
    ↓
audit_core/orchestrator.py (AuditOrchestrator)
    ↓
ingest → analyzers → agents → evidence → knowledge/report
    ↓
AuditResult
```

### Mainline Flow

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         Primary Entry Point                                  │
│                     POST /scan (api/routes/scan.py)                          │
└─────────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                    AuditOrchestrator                                         │
│              (audit_core/orchestrator.py)                                    │
│  - Coordinates the entire audit workflow                                     │
│  - Manages data flow between components                                      │
└─────────────────────────────────────────────────────────────────────────────┘
                                    │
          ┌─────────────────────────┼─────────────────────────┐
          │                         │                         │
          ▼                         ▼                         ▼
┌──────────────┐        ┌──────────────┐        ┌──────────────┐
│    ingest    │        │   analyzers  │        │    agents    │
│              │        │              │        │              │
│ Code loading │        │ Pattern      │        │ ReconAgent   │
│ Language     │        │ AST          │        │ AnalysisAgent│
│ detection    │        │ Taint        │        │ JudgeAgent   │
└──────────────┘        └──────────────┘        └──────────────┘
          │                         │                         │
          └─────────────────────────┼─────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                         evidence                                             │
│  - Snippet extraction                                                        │
│  - Call chain construction                                                   │
│  - Confidence ledger                                                         │
│  - Evidence bundle assembly                                                  │
└─────────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                       knowledge / report                                     │
│  - CWE classification                                                        │
│  - RAG retrieval                                                             │
│  - Vulnerability graph                                                       │
│  - Report generation (JSON/Markdown/HTML)                                    │
└─────────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                         AuditResult                                          │
│  - summary: Audit statistics                                                 │
│  - findings: List of RawFinding                                              │
│  - evidence: List of EvidenceBundle                                          │
│  - agent_logs: Execution trace                                               │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Architecture Diagram (Full)

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              VulnPatch Platform                              │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                         API Layer                                    │   │
│  │  ┌──────────┐  ┌──────────┐  ┌───────────┐  ┌───────────┐          │   │
│  │  │ POST     │  │ GET      │  │ GET       │  │ GET       │          │   │
│  │  │ /scan    │  │ /health  │  │ /findings │  │ /report   │          │   │
│  │  │ (primary)│  │          │  │ /evidence │  │ /agents   │          │   │
│  │  └──────────┘  └──────────┘  │ /logs     │  │ /json     │          │   │
│  │                              └───────────┘  └───────────┘            │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                    │                                         │
│                                    ▼                                         │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                    AuditOrchestrator                                 │   │
│  │              (Main entry point for audit workflow)                   │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                    │                                         │
│          ┌─────────────────────────┼─────────────────────────┐              │
│          │                         │                         │              │
│          ▼                         ▼                         ▼              │
│  ┌──────────────┐        ┌──────────────┐        ┌──────────────┐         │
│  │    ingest    │        │   analyzers  │        │    agents    │         │
│  │              │        │              │        │              │         │
│  │ Code loading │        │ Pattern      │        │ ReconAgent   │         │
│  │ Language     │        │ AST          │        │ AnalysisAgent│         │
│  │ detection    │        │ Taint        │        │ JudgeAgent   │         │
│  └──────────────┘        └──────────────┘        └──────────────┘         │
│          │                         │                         │              │
│          └─────────────────────────┼─────────────────────────┘              │
│                                    │                                         │
│                                    ▼                                         │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                         evidence                                     │   │
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────────────┐ │   │
│  │  │ Snippets    │  │ Call Chains │  │ Confidence Ledger           │ │   │
│  │  └─────────────┘  └─────────────┘  └─────────────────────────────┘ │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                    │                                         │
│                                    ▼                                         │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                       knowledge                                      │   │
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────────────┐ │   │
│  │  │ CWE Mapper  │  │ RAG         │  │ Vuln Graph                  │ │   │
│  │  └─────────────┘  └─────────────┘  └─────────────────────────────┘ │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                    │                                         │
│                                    ▼                                         │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                        report                                        │   │
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────────────┐ │   │
│  │  │ JSON        │  ┌─────────────┐  ┌─────────────────────────────┐ │   │
│  │  │ JSON        │  │ Markdown    │  │ HTML                        │ │   │
│  │  └─────────────┘  └─────────────┘  └─────────────────────────────┘ │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Data Flow

### Audit Pipeline
```
Input → ingest → CodeUnit → analyzers → RawFinding → merge → agents → 
EvidenceBundle → knowledge → report → AuditResult
```

---

## Core Components

### audit_core

Central data models and orchestration logic.

- **models.py**: Pydantic models for all data types
- **orchestrator.py**: Main audit workflow orchestrator (AuditOrchestrator)
- **registry.py**: Analyzer registration and discovery
- **result_merger.py**: Finding deduplication
- **scoring.py**: Risk score calculation
- **agent_runtime.py**: Agent execution with error isolation
- **error_policy.py**: Fallback strategies for Agent failures

#### AuditOrchestrator vs OrchestratorAgent

**AuditOrchestrator** (`audit_core/orchestrator.py`):
- **性质**: 确定性工程编排器，不直接依赖 LLM
- **职责**: 扫描主流程、模块调度、错误恢复、analyzer 语言路由
- **当前状态**: ✅ 已实现，是唯一的工程主流程入口
- **接入方式**: 所有功能通过 `AuditOrchestrator` 接入 `/scan`

**OrchestratorAgent** (`agents/orchestrator_agent.py`):
- **性质**: 可选 LLM 策略协调 Agent
- **职责**（未来）: 多 Agent 推理规划、动态策略协调
- **当前状态**: 📝 占位实现，不承担主流程调度
- **限制**: 不直接控制 API、不直接调用 analyzer、不替代 AuditOrchestrator

**Agent 接入主流程的方式**:
1. 通过 `AuditOrchestrator`: 修改 `audit_core/orchestrator.py` 调用新 Agent
2. 通过 `AgentRuntime`: 使用 `audit_core/agent_runtime.py` 的错误隔离机制

**不要**将 Agent 注册到 `agents/orchestrator_agent.py` 作为当前主流程的接入方式。

### ingest

Input handling and code loading.

- **repo_loader.py**: Load code from various sources
- **code_unit_builder.py**: Build CodeUnit objects
- **language_router.py**: Language detection

### analyzers

Static analysis engines.

- **base.py**: Base analyzer interface
- **pattern_analyzer.py**: Regex-based detection
- **ast_analyzer.py**: AST-based detection
- **taint/**: Taint analysis engine
- **python/**: Python analyzer (AST/Regex/Taint engines)
- **javascript/**: JavaScript/TypeScript analyzers
- **java/**: Java analyzers
- **c_cpp/**: C/C++ analyzers

### agents

LLM-powered analysis agents.

- **base_agent.py**: Base agent interface
- **recon_agent.py**: Initial code inspection
- **analysis_agent.py**: Finding analysis
- **judge_agent.py**: Final verdict
- **orchestrator_agent.py**: Multi-agent coordination

### evidence

Evidence collection and management.

- **snippet_extractor.py**: Code snippet extraction
- **call_chain_builder.py**: Call chain construction
- **confidence_ledger.py**: Confidence tracking
- **evidence_builder.py**: Evidence bundle assembly

### knowledge

Knowledge base and classification.

- **cwe_mapper.py**: CWE classification
- **rag_retriever.py**: RAG retrieval
- **vuln_graph.py**: Vulnerability graph

### report

Report generation.

- **json_report.py**: JSON output
- **markdown_report.py**: Markdown output
- **html_report.py**: HTML output

### api

FastAPI routes and schemas.

- **schemas.py**: Pydantic request/response models
- **routes/scan.py**: Primary scan endpoint
- **routes/findings.py**: Findings endpoint
- **routes/evidence.py**: Evidence endpoint
- **routes/agents.py**: Agent logs endpoint
- **routes/report.py**: Report generation endpoints

---

## Key Design Principles

1. **Single Entry Point**: All functionality must use `/scan` + `AuditOrchestrator`
2. **Separation of Concerns**: Analyzers do static analysis, Agents do LLM reasoning
3. **Unified Data Models**: All components use standardized Pydantic models
4. **Extensibility**: New analyzers and agents can be added via registry
5. **Multi-Language Support**: Independent analyzers for Python, JavaScript, Java, C/C++

---

## Usage

### Basic Scan

```python
from audit_core.orchestrator import AuditOrchestrator

orchestrator = AuditOrchestrator()

# Scan code snippet
result = orchestrator.scan_code("def hello(): pass", language="python")

# Scan local repository
result = orchestrator.scan_path("/path/to/repo")

# Full scan API
result = orchestrator.scan(
    input_type="code",
    code="def hello(): pass",
    language="python"
)
```

### API Endpoints

**Primary endpoints**:
- `POST /scan` - Primary scan endpoint (delegates to AuditOrchestrator)
- `GET /findings` - Findings from most recent scan
- `GET /evidence` - Evidence bundles from most recent scan
- `GET /agents/logs` - Agent logs from most recent scan
- `GET /report/json` - Full audit result as JSON
- `GET /report/markdown` - Audit report as Markdown
- `GET /report/html` - Audit report as HTML
- `GET /health` - Health check

---

## Analyzer Language Routing

The audit pipeline implements language-based analyzer routing to ensure each analyzer only processes code units of supported languages:

### Routing Flow

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    AuditOrchestrator._run_analyzers()                        │
│                                                                              │
│  1. Group code_units by language                                             │
│     _group_code_units_by_language(code_units)                               │
│         → {"python": [...], "javascript": [...], "java": [...]}             │
│                                                                              │
│  2. For each language group:                                                 │
│     ├── Get analyzers: registry.get_analyzers_for_language(language)        │
│     ├── Run each analyzer on language-specific code_units                    │
│     └── Handle exceptions (log and continue)                                │
│                                                                              │
│  3. Skip "unknown" language:                                                 │
│     ├── No analyzer runs on unknown language                                │
│     └── Recorded in metadata["skipped_languages"]                           │
│                                                                              │
│  4. Return: (findings, analyzer_metadata)                                   │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Language Grouping

Code units are grouped by their `language` attribute (normalized to lowercase):

| Language | Analyzers |
|----------|-----------|
| `python` | PythonAnalyzer, PatternAnalyzer, TaintAnalyzer |
| `javascript` / `js` | JSAnalyzer, PatternAnalyzer |
| `java` | JavaAnalyzer |
| `c` / `cpp` | CAnalyzer, CppAnalyzer |
| `unknown` | **Skipped** (no analyzer) |

### Unknown Language Handling

When a code unit has `language="unknown"`:
- **No analyzer runs on it** - skipped entirely
- **Logged as warning** with reason
- **Recorded in metadata** under `skipped_languages`
- **Does not crash the scan**

### Analyzer Error Handling

When an analyzer throws an exception:
- **Exception is caught** in `_run_analyzers()`
- **Error is logged** with analyzer name, language, error type/message
- **Other analyzers continue** executing
- **Error recorded in metadata** under `analyzer_errors`
- **Scan does not crash**

### Metadata Structure

The `_run_analyzers()` method returns analyzer metadata:

```python
{
    "analyzer_runs": [
        {"analyzer_name": "...", "language": "...", "success": True, "finding_count": N}
    ],
    "analyzer_errors": [
        {"analyzer_name": "...", "language": "...", "error_type": "...", "error_message": "..."}
    ],
    "skipped_languages": [
        {"language": "unknown", "code_unit_count": N, "reason": "..."}
    ]
}
```

This metadata is stored in `AuditResult.metadata["analyzer_info"]`.

### Benefits

1. **Performance**: Analyzers only process relevant code units
2. **Accuracy**: Language-specific analysis reduces false positives
3. **Clarity**: Clear responsibility boundaries per analyzer
4. **Resilience**: Analyzer failures don't crash the scan

---

## Error Handling and Recovery

The audit pipeline implements comprehensive error isolation and degradation strategies to ensure scan reliability:

### AgentRuntime Error Isolation

The `AgentRuntime` class (`audit_core/agent_runtime.py`) wraps all Agent calls with try/except blocks to prevent individual Agent failures from crashing the entire scan:

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         AgentRuntime                                         │
│              (audit_core/agent_runtime.py)                                   │
│                                                                              │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐    │
│  │  run_recon   │  │ run_analysis │  │  run_judge   │  │build_evidence│    │
│  │              │  │              │  │              │  │              │    │
│  │ try:         │  │ try:         │  │ try:         │  │ try:         │    │
│  │   agent.run  │  │   agent.run  │  │   agent.run  │  │   build...   │    │
│  │ except:      │  │ except:      │  │ except:      │  │ except:      │    │
│  │   fallback   │  │   fallback   │  │   fallback   │  │   log only   │    │
│  └──────────────┘  └──────────────┘  └──────────────┘  └──────────────┘    │
└─────────────────────────────────────────────────────────────────────────────┘
```

### ErrorPolicy Fallback Strategies

The `ErrorPolicy` class (`audit_core/error_policy.py`) defines degradation strategies for different failure scenarios:

| Stage | Failure Strategy | Fallback Output |
|-------|-----------------|-----------------|
| **Recon** | Log failure, continue | Empty hypotheses list `[]` |
| **Analysis** | Generate low-confidence hypothesis, continue | `AgentHypothesis(confidence="low", fallback_applied=True)` |
| **Judge** | Generate conservative decision, continue | `JudgeDecision(verdict="suspicious", confidence="low", risk_score=30)` |
| **Evidence** | Log failure, preserve finding | `None` (finding still in results) |

### AgentExecutionResult

All Agent executions return an `AgentExecutionResult` with:
- `status`: `"success"`, `"degraded"`, `"failed"`, or `"skipped"`
- `output`: The actual output (hypothesis, decision, etc.)
- `logs`: Structured `AgentLog` entries
- `error`: Exception information (if failed)
- `fallback_used`: Boolean indicating if fallback was applied

### Benefits

1. **Resilience**: Individual Agent failures don't crash the entire scan
2. **Observability**: All failures are logged with structured metadata
3. **Graceful Degradation**: Fallback outputs allow the pipeline to continue
4. **Conservative Defaults**: Fallback decisions use conservative values (e.g., `verdict="suspicious"`, `risk_score=30`)

---

## Future Work

- [ ] Implement full AST analysis
- [ ] Implement taint flow analysis
- [ ] Add real LLM integration for agents
- [ ] Implement GitHub repository scanning
- [ ] Add RAG-based knowledge retrieval
- [ ] Build vulnerability knowledge graph
- [ ] Add more vulnerability patterns
- [ ] Enhance multi-language support
