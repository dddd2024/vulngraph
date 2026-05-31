# VulnPatch AI 协作治理规范

## 项目定位

VulnPatch 是一个模块化安全审计平台，结合静态分析与 LLM 推理能力检测源代码漏洞。

**当前阶段**: Stage 2.1（多人协作架构补强完成，Agent Registry + Taint 统一 + UI 契约对齐）

**核心目标**: 建立 AI 协作治理机制，确保四位成员在并行开发时遵守架构边界和契约。

**已完成治理增强**:
- ✅ 四人任务模板补齐（TASKS/*.md）
- ✅ Analyzer Registry 插件化（支持按语言路由）
- ✅ Agent Registry 插件化（`agents/registry.py` + `agents/register_builtin.py`）
- ✅ Agent 强类型接口（BaseAgent + AgentRuntime 错误隔离）
- ✅ /scan session 化（支持多扫描隔离）
- ✅ 模块化测试目录（tests/test_<module>/）
- ✅ Taint 入口统一（顶层 TaintAnalyzer 委托给 python/engines/taint_engine.py）
- ✅ UI 契约对齐（前端使用 /scan，渲染 findings 而非 vulnerabilities）

**阶段说明**:
- 可以按四人任务模板进入模块能力填充
- 各模块负责人可按 TASKS/*.md 推进功能实现
- 保持架构边界和公共契约稳定

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
7. **禁止** 基于 `main.py`、`analysis_engine.py`、`api/routes/legacy.py` 开发新功能
8. **禁止** 新代码导入 `analysis_engine` 或 `main` 模块
9. **禁止** 导入已删除的 `detector/` 模块

### 必须遵守
1. **必须** 通过 `AuditOrchestrator` 接入主流程
2. **必须** 遵守模块边界（见四人分工）
3. **必须** 运行测试后提交

### 旧入口限制
以下文件已标记为**待移除**，新功能不得接入：
- `main.py` - 旧 pipeline 入口，使用 detector/ 和 parser/ 直接扫描
- `analysis_engine.py` - 旧输入分析入口，直接调用 detector 和 parser
- `api/routes/legacy.py` - 旧 API 路由，仅保留向后兼容

**所有新功能必须通过 `AuditOrchestrator` 接入 `/scan` 入口。**

---

## AuditOrchestrator vs OrchestratorAgent

### 明确区分

| 组件 | 类型 | 职责 | 当前状态 |
|------|------|------|----------|
| **AuditOrchestrator** | 确定性工程编排器 | 扫描主流程、模块调度、错误恢复 | ✅ 已实现，主流程入口 |
| **OrchestratorAgent** | 可选 LLM 策略协调 Agent | 多 Agent 推理规划、动态策略 | 📝 未来可选，占位状态 |

### AuditOrchestrator（当前主流程）

- **位置**: `audit_core/orchestrator.py`
- **性质**: 确定性工程编排器，不直接依赖 LLM
- **职责**:
  - 协调整个审计工作流
  - 管理模块间数据流
  - 实现错误隔离和恢复（AgentRuntime）
  - 按语言路由 analyzer
- **接入方式**: 所有功能通过 `AuditOrchestrator` 接入 `/scan`

### OrchestratorAgent（未来可选）

- **位置**: `agents/orchestrator_agent.py`
- **性质**: 可选 LLM 策略协调 Agent
- **职责**（未来）:
  - 多 Agent 推理规划
  - 动态策略协调
  - 不直接控制 API
  - 不直接调用 analyzer
  - **不替代** AuditOrchestrator
- **当前状态**: 占位实现，不承担主流程调度

### Agent 接入方式

新增 Agent 必须通过以下方式接入主流程：
1. **通过 AgentRegistry 注册**: 在 `agents/register_builtin.py` 中注册新 Agent
2. **通过 AuditOrchestrator**: `AuditOrchestrator` 从 `AgentRegistry` 获取默认 Agent，无需硬编码 Agent 类
3. **通过 AgentRuntime**: 使用 `audit_core/agent_runtime.py` 的错误隔离机制

**Agent Registry 机制**（Stage 2.1 新增）:
- `agents/registry.py` — `AgentRegistry` 类，提供 `register()`、`get()`、`get_recon()`、`get_analysis()`、`get_judge()` 等方法
- `agents/register_builtin.py` — 内置 Agent 注册入口，注册 ReconAgent、AnalysisAgent、JudgeAgent
- `build_default_agent_registry()` — 构建预装所有内置 Agent 的 registry
- `AuditOrchestrator` 接受可选 `agent_registry` 参数，默认使用 `build_default_agent_registry()`
- 新增 Agent 只需修改 `agents/register_builtin.py`，无需修改 `AuditOrchestrator`

**不要**将 Agent 注册到 `agents/orchestrator_agent.py` 作为当前主流程的接入方式。

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
- 实现 ReconAgent、AnalysisAgent、JudgeAgent
- 维护 Agent Registry（`agents/registry.py`、`agents/register_builtin.py`）
- 新增 Agent 通过 `register_builtin_agents()` 注册到 `AgentRegistry`
- LLM 集成（AnalysisAgent 的 LLM 分析模式）
- 实现 CWE 映射和知识图谱
- 证据构建和证据包管理

**允许修改**:
- `agents/*.py`（包括 `agents/registry.py`、`agents/register_builtin.py`）
- `knowledge/*.py`
- `evidence/*.py`
- `tests/test_agents*.py`, `tests/test_knowledge*.py`

**禁止**:
- 直接读取文件系统（使用 CodeUnit）
- 修改 `audit_core/models.py`
- 修改 Analyzers
- 在 Agent 中实现检测逻辑（检测由 Analyzer 负责）

**Agent 接入方式**:
- 新增 Agent 通过 `agents/register_builtin.py` 注册到 `AgentRegistry`
- `AuditOrchestrator` 自动从 `AgentRegistry` 获取 Agent，无需硬编码
- `OrchestratorAgent` 仅作为未来可选的 LLM 策略协调 Agent，不承担当前工程主流程调度

### 成员 4: API, UI & Report

**负责模块**:
- `api/` - API 路由
- `report/` - 报告生成
- `ui/` - 用户界面

**职责**:
- 维护 API 路由（以 `POST /scan` 为主入口）
- 实现报告生成器（JSON/Markdown/HTML）
- 维护 UI 组件
- 确保 API 契约合规（/scan 返回 summary、findings、evidence、agent_logs）
- UI 前端使用 `/scan` 同步接口，渲染 `result.findings`（非 `result.vulnerabilities`）

**UI / API 契约**（Stage 2.1 对齐）:
- 前端 `ui/app.js` 调用 `POST /scan` 获取扫描结果（不再使用 `/analyze-input-async` + `/jobs/{id}` 轮询）
- 扫描结果字段映射：`result.findings`（漏洞列表）、`result.evidence`（证据包）、`result.agent_logs`（Agent 日志）
- UI 渲染漏洞列表时从 `result.findings` 读取，每条 finding 包含 `type`、`severity`、`risk_score`、`file_path`、`start_line` 等字段
- 原始 JSON 展示保留完整的 /scan 响应

**允许修改**:
- `api/*.py`, `api/routes/*.py`
- `report/*.py`
- `ui/*.js`, `ui/*.html`, `ui/*.css`
- `tests/test_api*.py`, `tests/test_report*.py`

**禁止**:
- 在 API 中实现检测规则
- 修改 `audit_core/models.py`
- 修改 Analyzers 或 Agents
- 在前端实现任何扫描逻辑

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
python -m pytest tests/test_<module>.py -v

# 运行端到端测试
python -c "from audit_core.orchestrator import AuditOrchestrator; o = AuditOrchestrator(); print(o.scan_code('def test(): pass', 'python'))"
```

### 紧急联系

- **架构问题**: @Core Orchestrator 负责人
- **契约变更**: 全员讨论
- **跨模块冲突**: @Core Orchestrator 协调

---

*最后更新: 2026-05-31*
*版本: v1.2 - Stage 2.1 多人协作架构补强*
