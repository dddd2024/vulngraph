# VulnPatch 测试指南

## 测试结构

```
tests/
  contracts/           # 契约测试（所有人必须运行）
  test_core/           # Core Orchestrator 模块测试
  test_ingest/         # Ingest 模块测试
  test_analyzers/      # Analyzer & Taint Engine 模块测试
  test_agents/         # Agent & Knowledge 模块测试（含 evidence、knowledge smoke test）
  test_evidence/       # Evidence 模块测试
  test_knowledge/      # Knowledge 模块测试
  test_report/         # Report 模块测试
  test_api/            # API 模块测试
  test_integration/    # 端到端集成测试
  fixtures/            # 测试固件（各语言漏洞代码样本）
```

## 四类成员各自运行的测试

### 所有人必须运行（每次提交前）

```bash
# 架构守卫检查
python governance/architecture_guard.py

# 契约测试
python -m pytest tests/contracts/ -v
```

### 成员 1: Core Orchestrator

负责模块：`audit_core/`, `ingest/`, `governance/`, `contracts/`

```bash
# 模块测试
python -m pytest tests/test_core/ tests/test_ingest/ -v

# 集成测试（修改 orchestrator 时）
python -m pytest tests/test_integration/ -v
```

### 成员 2: Analyzer & Taint Engine

负责模块：`analyzers/`, `analyzers/taint/`

```bash
# 模块测试
python -m pytest tests/test_analyzers/ -v
```

### 成员 3: Agent & Knowledge

负责模块：`agents/`, `evidence/`, `knowledge/`

```bash
# 模块测试
python -m pytest tests/test_agents/ tests/test_evidence/ tests/test_knowledge/ -v
```

### 成员 4: API / Report / UI

负责模块：`api/`, `report/`, `ui/`

```bash
# 模块测试
python -m pytest tests/test_api/ tests/test_report/ -v
```

### 集成测试（可选，建议合并前运行）

```bash
python -m pytest tests/test_integration/ -v
```

## 运行全部测试

```bash
python -m pytest tests/ -v
```

## Smoke Tests 说明

每个模块目录下都有 `test_smoke.py`，包含最基本的冒烟测试：

| 模块 | Smoke Test 验证内容 |
|------|---------------------|
| core | AuditOrchestrator 可初始化、数据模型可创建、registry 可用 |
| ingest | 语言检测正确、CodeUnit 可构建 |
| analyzers | 默认 registry 包含所有 analyzer、analyzer 输出 RawFinding |
| agents | 三个 Agent 可实例化、返回类型正确、fallback 可用 |
| evidence | EvidenceBundle 可构建 |
| knowledge | CWE mapper / RAG / 图谱模块可导入 |
| report | JSON/Markdown/HTML 报告可生成 |
| api | /scan 返回 scan_id 和所有必需字段、旧接口兼容 |
| integration | 完整 scan_code 流程可跑通 |

## 旧测试兼容性

旧的测试文件仍然保留在 `tests/` 根目录下（如 `test_audit_core.py`、`test_scan_api.py` 等），
pytest 会同时发现并运行它们。新的模块化测试在 `tests/test_*/` 子目录中，
两者互不冲突。
