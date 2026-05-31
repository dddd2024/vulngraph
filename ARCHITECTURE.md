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
- **orchestrator.py**: Main audit workflow orchestrator
- **registry.py**: Analyzer registration and discovery
- **result_merger.py**: Finding deduplication
- **scoring.py**: Risk score calculation

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

## Future Work

- [ ] Implement full AST analysis
- [ ] Implement taint flow analysis
- [ ] Add real LLM integration for agents
- [ ] Implement GitHub repository scanning
- [ ] Add RAG-based knowledge retrieval
- [ ] Build vulnerability knowledge graph
- [ ] Add more vulnerability patterns
- [ ] Enhance multi-language support
