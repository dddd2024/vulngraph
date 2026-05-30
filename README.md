# VulnPatch

基于多 Agent 与程序分析的应用安全审计平台

## 项目定位

VulnPatch 是一个模块化安全审计平台，结合静态分析与 LLM 推理能力检测源代码漏洞。

**核心流程**：
```
代码输入 → 项目解析 → 攻击面识别 → 静态分析/污点分析 → LLM Agent 漏洞假设 → 证据链 → Judge Agent 裁决 → 审计报告
```

## 架构概览

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              VulnPatch Platform                              │
├─────────────────────────────────────────────────────────────────────────────┤
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
│  │  │ JSON        │  │ Markdown    │  │ HTML                        │ │   │
│  │  └─────────────┘  └─────────────┘  └─────────────────────────────┘ │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────────────┘
```

## 数据流

```
Input → ingest → CodeUnit → analyzers → RawFinding → merge → agents →
EvidenceBundle → knowledge → report → AuditResult
```

## 核心模块

- **audit_core**: 核心数据模型和编排逻辑
- **ingest**: 输入处理和代码加载
- **analyzers**: 静态分析引擎（Pattern、AST、Taint）
- **agents**: LLM 驱动的分析 Agent（Recon、Analysis、Judge）
- **evidence**: 证据收集和管理
- **knowledge**: 知识库和分类（CWE、RAG、Vuln Graph）
- **report**: 报告生成（JSON/Markdown/HTML）
- **api**: FastAPI 路由和接口

## 快速开始

### 安装依赖

```bash
pip install -r requirements.txt
```

### 运行架构守卫检查

```bash
python governance/architecture_guard.py
```

### 运行契约测试

```bash
python -m pytest tests/contracts/ -v
```

### 运行完整审计流程

```python
from audit_core.orchestrator import AuditOrchestrator

orchestrator = AuditOrchestrator()

# 扫描代码片段
result = orchestrator.scan_code("def hello(): pass", language="python")

# 扫描本地仓库
result = orchestrator.scan_path("/path/to/repo")
```

### 启动 API 服务

```bash
python api/server.py
```

## API 端点

**主入口**：
- `POST /scan` - 主扫描端点（委托给 AuditOrchestrator）
- `GET /findings` - 最近扫描的发现
- `GET /evidence` - 最近扫描的证据包
- `GET /agents/logs` - 最近扫描的 Agent 日志
- `GET /report/json` - JSON 格式的完整审计结果
- `GET /report/markdown` - Markdown 格式的审计报告
- `GET /report/html` - HTML 格式的审计报告
- `GET /health` - 健康检查

## 文档

- [AGENTS.md](AGENTS.md) - AI 协作治理规范
- [AI_COLLABORATION.md](AI_COLLABORATION.md) - AI 协作指南
- [ARCHITECTURE.md](ARCHITECTURE.md) - 架构文档
- [TASKS/core_orchestrator_task.md](TASKS/core_orchestrator_task.md) - Core Orchestrator 任务模板
- [TASKS/analyzer_taint_task.md](TASKS/analyzer_taint_task.md) - Analyzer & Taint Engine 任务模板

## 开发规范

1. **模块边界清晰** - 每个模块只负责特定功能
2. **公共契约稳定** - 修改公共契约需全员讨论
3. **测试驱动** - 提交前必须运行测试
4. **文档同步** - 修改行为需同步更新文档

## 许可证

MIT
