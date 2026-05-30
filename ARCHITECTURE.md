# VulnPatch Architecture

## Overview

VulnPatch is a modular security audit platform that combines static analysis with LLM-powered reasoning to detect and analyze vulnerabilities in source code.

## Architecture Diagram

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              VulnPatch Platform                              │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                         API Layer                                    │   │
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────────────┐ │   │
│  │  │ /scan/new   │  │ /health     │  │ /scan (legacy)              │ │   │
│  │  │ (new)       │  │             │  │ (backward compatible)       │ │   │
│  │  └─────────────┘  └─────────────┘  └─────────────────────────────┘ │   │
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
│  │  │ JSON        │  │ Markdown    │  │ HTML                        │ │   │
│  │  └─────────────┘  └─────────────┘  └─────────────────────────────┘ │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

## Data Flow

```
Input → ingest → CodeUnit → analyzers → RawFinding → merge → agents → 
EvidenceBundle → knowledge → report → AuditResult
```

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
- **ast_analyzer.py**: AST-based detection (skeleton)
- **taint/**: Taint analysis engine (skeleton)
- **legacy_adapter.py**: Legacy detector integration

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
- **rag_retriever.py**: RAG retrieval (skeleton)
- **vuln_graph.py**: Vulnerability graph (skeleton)
- **legacy_graph_adapter.py**: Legacy graph integration

### report

Report generation.

- **json_report.py**: JSON output
- **markdown_report.py**: Markdown output
- **html_report.py**: HTML output

### api

FastAPI routes and schemas.

- **schemas.py**: Pydantic request/response models
- **routes/scan.py**: New scan endpoint
- **routes/health.py**: Health check
- **routes/legacy.py**: Backward compatibility

## Key Design Principles

1. **Separation of Concerns**: Analyzers do static analysis, Agents do LLM reasoning
2. **Unified Data Models**: All components use standardized Pydantic models
3. **Extensibility**: New analyzers and agents can be added via registry
4. **Backward Compatibility**: Legacy API endpoints are preserved
5. **No LLM Calls in Stage 1**: Agents use placeholder logic initially

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

- `POST /scan/new` - New scan endpoint
- `GET /health` - Health check
- `POST /scan` - Legacy scan endpoint (backward compatible)

## Future Work

- [ ] Implement full AST analysis
- [ ] Implement taint flow analysis
- [ ] Add real LLM integration for agents
- [ ] Implement GitHub repository scanning
- [ ] Add RAG-based knowledge retrieval
- [ ] Build vulnerability knowledge graph
- [ ] Integrate with legacy graph module
- [ ] Add more vulnerability patterns
- [ ] Implement multi-language support
