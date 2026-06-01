## 变更摘要
<!-- 简要描述本次 PR 的目的和内容 -->

## 修改模块

- [ ] `audit_core/` - Core Orchestrator
- [ ] `ingest/` - 输入处理
- [ ] `analyzers/` - 静态分析器
- [ ] `agents/` - LLM Agent
- [ ] `evidence/` - 证据收集
- [ ] `knowledge/` - 知识库
- [ ] `api/` - API 路由
- [ ] `report/` - 报告生成
- [ ] `ui/` - 用户界面
- [ ] `governance/` - 架构治理
- [ ] `contracts/` - 契约定义
- [ ] `tests/` - 测试

## 是否修改公共契约

公共契约文件：`audit_core/models.py`、`contracts/*.schema.json`、`governance/module_boundaries.yaml`、`ARCHITECTURE.md`、`AGENTS.md`

- [ ] 否，未修改公共契约
- [ ] 是，已修改以下公共契约文件（需说明原因并确认已获全员同意）：
  - <!-- 列出修改的公共契约文件 -->

## 已运行测试

- [ ] `python governance/architecture_guard.py` 通过
- [ ] `python -m pytest tests/contracts/ -v` 通过
- [ ] `python -m pytest tests/ -v` 通过

## 其他说明
<!-- 如有需要补充的信息请在此说明 -->
