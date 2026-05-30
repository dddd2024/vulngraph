# VulnPatch AI 协作治理规范

## 项目定位

VulnPatch 是一个模块化安全审计平台，结合静态分析与 LLM 推理能力检测源代码漏洞。

**当前阶段**: Stage 1.5 AI 协作治理层

**核心目标**: 建立 AI 协作治理机制，确保四位成员在并行开发时遵守架构边界和契约。

**阶段限制**:
- 不要新增检测能力（保持现有 PatternAnalyzer 即可）
- 不要实现完整污点流（taint/ 目录保持骨架）
- 不要接入真实 LLM（agents/ 保持占位逻辑）
- 不要修改前端功能
- 后续 Stage 2 才允许按模块任务模板新增功能

---

## 核心架构规则

### 1. 分层架构（严格禁止跨层调用）

```
Input → ingest → CodeUnit → analyzers → RawFinding → agents → 
EvidenceBundle → knowledge → report → AuditResult
```

**规则**:
- `analyzers/` 只能输出 `RawFinding`，不能调用 `agents` 或 `llm`
- `agents/` 只能处理结构化对象，不能直接扫描文件系统
- `api/` 只负责路由和序列化，不能包含检测规则实现
- `ingest/` 只负责输入处理，不能包含分析逻辑

### 2. 数据流向（单向）

- 允许: `ingest` → `analyzers` → `agents` → `evidence` → `knowledge` → `report`
- 禁止: 任何反向依赖或跳过中间层的直接调用

### 3. 公共契约（不可擅自修改）

以下文件为公共契约，修改需全员讨论：
- `audit_core/models.py` - 核心数据模型
- `contracts/*.schema.json` - JSON Schema 约束
- `governance/public_contracts.yaml` - 公共契约声明
- `governance/module_boundaries.yaml` - 模块边界定义
- `ARCHITECTURE.md` - 架构文档

---

## 禁止事项

### 绝对禁止
1. **禁止** `analyzers/` 导入 `agents` 或 `llm` 模块
2. **禁止** `analyzers/` 直接调用 LLM API
3. **禁止** `agents/` 直接读取文件系统（只能通过结构化对象）
4. **禁止** `api/` 包含漏洞检测规则实现
5. **禁止** 修改 `audit_core/models.py` 中的字段定义
6. **禁止** 删除或修改 `/scan` 返回的必需字段

### 阶段限制（第一阶段）
1. **不要** 实现新的漏洞检测能力（保持现有 PatternAnalyzer 即可）
2. **不要** 实现完整污点流（taint/ 目录保持骨架）
3. **不要** 实现完整 Agent LLM 调用（保持占位逻辑）
4. **不要** 修改前端功能
5. **不要** 修改 UI 相关代码

---

## 公共契约文件

### 核心数据模型（audit_core/models.py）

| 模型 | 用途 | 关键字段 |
|------|------|----------|
| `CodeUnit` | 代码输入单元 | `id`, `path`, `language`, `content` |
| `RawFinding` | 分析器输出 | `id`, `rule_id`, `type`, `severity`, `confidence` |
| `AgentHypothesis` | Agent 假设 | `id`, `agent_name`, `finding_id`, `hypothesis` |
| `JudgeDecision` | 裁决结果 | `id`, `finding_id`, `verdict`, `risk_score` |
| `EvidenceBundle` | 证据包 | `id`, `finding`, `snippets`, `judge_decision` |
| `AuditResult` | 审计结果 | `summary`, `findings`, `evidence`, `agent_logs` |

### API 契约

`/scan` 返回必须包含：
```json
{
  "summary": {
    "total_code_units": int,
    "total_findings": int,
    "total_evidence_bundles": int,
    "risk_score": float,
    "languages": [str],
    "scanned_files": [str]
  },
  "findings": [...],
  "evidence": [...],
  "agent_logs": [...]
}
```

### JSON Schema（contracts/）

- `code_unit.schema.json` - CodeUnit 序列化约束
- `raw_finding.schema.json` - RawFinding 序列化约束
- `evidence_bundle.schema.json` - EvidenceBundle 序列化约束
- `audit_result.schema.json` - AuditResult 序列化约束
- `scan_response.schema.json` - /scan 响应约束

---

## 四人模块分工

### 成员 1: Core Orchestrator（架构负责人）

**负责模块**:
- `audit_core/` - 核心数据模型和编排器
- `ingest/` - 输入处理
- `governance/` - 架构治理
- `contracts/` - 契约定义

**职责**:
- 维护公共数据模型
- 维护模块边界和契约
- 审查跨模块改动
- 维护架构文档

**允许修改**:
- `audit_core/models.py`（需全员讨论）
- `audit_core/orchestrator.py`
- `ingest/*.py`
- `governance/*.yaml`, `governance/*.py`
- `contracts/*.json`

### 成员 2: Analyzer & Taint Engine

**负责模块**:
- `analyzers/` - 静态分析器
- `analyzers/taint/` - 污点分析引擎

**职责**:
- 实现 PatternAnalyzer 规则
- 实现 ASTAnalyzer
- 实现 TaintAnalyzer 污点流
- 维护检测规则库

**允许修改**:
- `analyzers/*.py`
- `analyzers/taint/*.py`
- `tests/test_analyzers*.py`

**禁止**:
- 导入 `agents` 或 `llm`
- 修改 `audit_core/models.py`
- 修改 API 路由

### 成员 3: Agent & Knowledge

**负责模块**:
- `agents/` - LLM Agent
- `knowledge/` - 知识库
- `evidence/` - 证据构建

**职责**:
- 实现 ReconAgent
- 实现 AnalysisAgent（LLM 集成）
- 实现 JudgeAgent
- 实现 CWE 映射和知识图谱

**允许修改**:
- `agents/*.py`
- `knowledge/*.py`
- `evidence/*.py`
- `tests/test_agents*.py`, `tests/test_knowledge*.py`

**禁止**:
- 直接读取文件系统（使用 CodeUnit）
- 修改 `audit_core/models.py`
- 修改 Analyzers

### 成员 4: API, UI & Report

**负责模块**:
- `api/` - API 路由
- `report/` - 报告生成
- `ui/` - 用户界面

**职责**:
- 维护 API 路由
- 实现报告生成器（JSON/Markdown/HTML）
- 维护 UI 组件
- 确保 API 契约合规

**允许修改**:
- `api/*.py`, `api/routes/*.py`
- `report/*.py`
- `ui/*.py`
- `tests/test_api*.py`, `tests/test_report*.py`

**禁止**:
- 在 API 中实现检测规则
- 修改 `audit_core/models.py`
- 修改 Analyzers 或 Agents

---

## 提交前测试要求

### 必须运行的测试

```bash
# 1. 契约测试（所有人）
python -m pytest tests/contracts/ -v

# 2. 模块边界检查（所有人）
python governance/architecture_guard.py

# 3. 自己模块的测试
python -m pytest tests/test_<your_module>/ -v

# 4. 集成测试（修改 orchestrator 时）
python -m pytest tests/test_integration.py -v
```

### 测试通过标准

- [ ] `tests/contracts/test_models_contract.py` - 数据模型可序列化
- [ ] `tests/contracts/test_scan_response_contract.py` - /scan 返回字段完整
- [ ] `tests/contracts/test_module_boundaries.py` - 无禁止的跨模块导入
- [ ] `governance/architecture_guard.py` - 架构检查通过
- [ ] 自己模块的单元测试全部通过

### 提交检查清单

```markdown
## 提交前检查清单

- [ ] 我的修改仅限于我的负责模块
- [ ] 我没有修改公共契约文件（如果修改了，已征得全员同意）
- [ ] 我没有跨模块导入禁止的依赖
- [ ] 所有契约测试通过
- [ ] 架构守卫检查通过
- [ ] 我的模块单元测试通过
- [ ] 我已更新相关 AGENTS.md（如果行为有变化）
- [ ] 我已更新 ARCHITECTURE.md（如果架构有变化）
```

---

## 跨模块改动流程

### 场景 1: 需要修改公共契约

1. 在群里发起讨论，说明修改原因
2. 所有成员同意后，由 Core Orchestrator 负责人修改
3. 更新相关 Schema 和文档
4. 全员同步更新自己的代码

### 场景 2: 需要调用其他模块

1. 检查是否已有公共接口
2. 如果没有，向 Core Orchestrator 提出接口需求
3. 由 Core Orchestrator 定义接口
4. 双方按接口实现

### 场景 3: 发现其他模块 Bug

1. 不要直接修改他人模块
2. 在 Issue 中报告，@相关负责人
3. 由负责人自己修复

---

## 协作工具使用

### Codex / Trae 使用规范

1. **开始前**: 在 AI_COLLABORATION.md 中查看当前任务范围
2. **Prompt 中**: 明确指定模块边界，例如：
   ```
   请修改 analyzers/pattern_analyzer.py，添加 SQL 注入检测规则。
   注意：
   - 不要导入 agents 或 llm
   - 输出必须是 RawFinding 类型
   - 遵守 analyzers/AGENTS.md 中的规范
   ```
3. **提交前**: 运行架构守卫检查
4. **PR 描述**: 说明修改范围、测试通过情况

---

## 文档维护责任

| 文档 | 维护责任人 | 更新时机 |
|------|-----------|----------|
| `AGENTS.md` (根目录) | Core Orchestrator | 架构规则变化时 |
| `ARCHITECTURE.md` | Core Orchestrator | 架构变化时 |
| `*/AGENTS.md` | 各模块负责人 | 模块行为变化时 |
| `governance/*.yaml` | Core Orchestrator | 契约变化时 |
| `contracts/*.json` | Core Orchestrator | 数据模型变化时 |
| `AI_COLLABORATION.md` | Core Orchestrator | 协作流程变化时 |
| `TASKS/*.md` | Core Orchestrator | 任务模板变化时 |

---

## 违规处理

### 自动阻止（通过测试/脚本）
- 禁止的跨模块导入 → `tests/contracts/test_module_boundaries.py`
- /scan 返回字段缺失 → `tests/contracts/test_scan_response_contract.py`
- 数据模型无法序列化 → `tests/contracts/test_models_contract.py`

### 人工审查
- 修改公共契约未讨论 → PR 被拒绝
- 跨模块改动未通知 → 回滚并重新提交
- 未运行测试就提交 → 要求补测

---

## 快速参考

### 常用命令

```bash
# 运行所有契约测试
python -m pytest tests/contracts/ -v

# 运行架构守卫
python governance/architecture_guard.py

# 运行特定模块测试
python -m pytest tests/test_analyzers.py -v

# 运行端到端测试
python -c "from audit_core.orchestrator import AuditOrchestrator; o = AuditOrchestrator(); print(o.scan_code('def test(): pass', 'python'))"
```

### 紧急联系

- **架构问题**: @Core Orchestrator 负责人
- **契约变更**: 全员讨论
- **跨模块冲突**: @Core Orchestrator 协调

---

*最后更新: 2026-05-30*
*版本: v1.0*
