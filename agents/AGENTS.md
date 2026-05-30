# Agents 模块治理规范

## 本模块职责

LLM 驱动的智能分析 Agent，负责对 Analyzers 的发现进行推理、验证和裁决。

**核心任务**:
- ReconAgent: 初始代码侦察
- AnalysisAgent: 漏洞分析和假设生成
- JudgeAgent: 最终裁决和风险评分
- OrchestratorAgent: 多 Agent 协调

**注意**: Agents 只处理结构化对象，**不直接读取文件系统**，**不直接扫描代码**。

---

## 允许输入

### 输入类型
- `CodeUnit` - 代码单元对象
- `RawFinding` - 分析器发现
- `AgentHypothesis` - 其他 Agent 的假设
- `EvidenceBundle` - 证据包

### 输入来源
- 仅通过 `run()` 方法参数接收输入
- 禁止直接读取文件系统
- 禁止直接扫描代码库

---

## 允许输出

### 输出类型
- `AgentHypothesis` - Agent 假设
- `AgentLog` - Agent 执行日志
- `JudgeDecision` - 裁决决定

### 输出要求
- `AgentHypothesis`: 必须包含 `agent_name`, `finding_id`, `hypothesis`, `confidence`
- `JudgeDecision`: 必须包含 `finding_id`, `verdict`, `risk_score`, `reason`

---

## 禁止跨模块行为

### 绝对禁止
1. ❌ **禁止直接读取文件系统**
   ```python
   # 禁止
   with open("some_file.py") as f:
       content = f.read()
   
   # 禁止
   import os
   for root, dirs, files in os.walk("/path/to/repo"):
       ...
   ```

2. ❌ **禁止直接扫描代码库**
   ```python
   # 禁止
   from ingest.repo_loader import RepoLoader
   loader = RepoLoader()
   units = loader.load_local_repo("/path/to/repo")
   ```

3. ❌ **禁止修改 `audit_core/models.py`**

4. ❌ **禁止修改 Analyzers**

5. ❌ **禁止在 Agent 中实现检测规则**

### 允许的内部导入
```python
# 允许
from audit_core.models import CodeUnit, RawFinding, AgentHypothesis
from agents.base_agent import BaseAgent
from evidence.snippet_extractor import extract_snippet
from knowledge.cwe_mapper import map_cwe
```

---

## 必须遵守的数据模型

### 输入模型
```python
# CodeUnit
class CodeUnit(BaseModel):
    id: str
    path: str
    language: str
    content: str
    start_line: int
    end_line: Optional[int]
    metadata: dict[str, Any]

# RawFinding
class RawFinding(BaseModel):
    id: str
    rule_id: str
    type: str
    severity: str
    confidence: str
    file_path: str
    start_line: int
    message: str
```

### 输出模型
```python
# AgentHypothesis
class AgentHypothesis(BaseModel):
    id: str
    agent_name: str
    finding_id: Optional[str]
    hypothesis: str
    vulnerability_type: Optional[str]
    reasoning_summary: str
    confidence: str
    supporting_evidence_ids: list[str]
    metadata: dict[str, Any]

# JudgeDecision
class JudgeDecision(BaseModel):
    id: str
    finding_id: str
    verdict: str  # confirmed, suspicious, rejected
    confidence: str
    risk_score: float
    reason: str
    metadata: dict[str, Any]

# AgentLog
class AgentLog(BaseModel):
    id: str
    agent_name: str
    stage: str
    message: str
    input_refs: list[str]
    output_refs: list[str]
    timestamp: datetime
    metadata: dict[str, Any]
```

---

## 实现规范

### 创建新 Agent

1. 继承 `BaseAgent`
2. 实现 `run()` 方法
3. 设置 `name` 类属性
4. 返回指定的输出类型

```python
from agents.base_agent import BaseAgent
from audit_core.models import RawFinding, AgentHypothesis, AgentLog

class MyAgent(BaseAgent):
    name = "my_agent"
    
    def run(self, finding: RawFinding) -> tuple[AgentHypothesis, AgentLog]:
        # 分析逻辑（可以调用 LLM）
        hypothesis = AgentHypothesis(
            agent_name=self.name,
            finding_id=finding.id,
            hypothesis="Potential vulnerability detected",
            reasoning_summary="Based on pattern analysis...",
            confidence="medium"
        )
        
        log = AgentLog(
            agent_name=self.name,
            stage="analysis",
            message=f"Analyzed finding {finding.id}",
            input_refs=[finding.id],
            output_refs=[hypothesis.id]
        )
        
        return hypothesis, log
```

### LLM 调用规范

```python
# 允许：在 Agent 中调用 LLM
class AnalysisAgent(BaseAgent):
    def run(self, finding: RawFinding, code_unit: CodeUnit):
        # 构建 prompt
        prompt = self._build_prompt(finding, code_unit)
        
        # 调用 LLM
        response = self.llm_client.complete(prompt)
        
        # 解析响应
        hypothesis = self._parse_response(response)
        
        return hypothesis, log
```

---

## 数据流规范

### 正确的数据流
```
Orchestrator → CodeUnit → Agent.run(CodeUnit) → AgentHypothesis
```

### 错误的数据流
```
Agent → 读取文件系统 → CodeUnit  # 禁止！
Agent → 调用 Analyzer → RawFinding  # 禁止！
```

---

## 提交前检查清单

- [ ] 我没有直接读取文件系统
- [ ] 我没有直接扫描代码库
- [ ] 我的 Agent 只处理结构化对象
- [ ] 我的 Agent 输出符合规定的模型
- [ ] 我没有修改 `audit_core/models.py`
- [ ] 我没有修改 Analyzers
- [ ] 所有单元测试通过
- [ ] 架构守卫检查通过

---

## 修改记录

| 日期 | 修改人 | 修改内容 |
|------|--------|----------|
| 2025-05-30 | Core Orchestrator | 初始版本 |
