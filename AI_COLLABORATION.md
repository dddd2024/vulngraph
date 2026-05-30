# VulnPatch AI 协作指南

## 概述

本文档说明四位成员如何使用 Codex / Trae 进行并行开发协作。

## 协作原则

1. **模块边界清晰** - 每个成员只修改自己的模块
2. **公共契约稳定** - 修改公共契约需全员讨论
3. **测试驱动** - 提交前必须运行测试
4. **文档同步** - 修改行为需同步更新文档

---

## 开始任务前如何限定 Scope

### 1. 查看当前任务

```bash
# 查看任务模板
cat TASKS/<your_module>_task.md
```

### 2. 确认修改范围

- 我的模块是哪些文件？
- 我可以修改什么？
- 我绝对不能修改什么？

### 3. 使用 Codex / Trae 时的 Prompt 模板

```
请帮我修改 <模块名> 模块，实现以下功能：

【功能描述】
...

【约束条件】
- 不要修改其他模块的文件
- 不要修改 audit_core/models.py
- 输出必须符合 RawFinding 模型
- 遵守 analyzers/AGENTS.md 中的规范
- 不要基于 main.py、analysis_engine.py、api/routes/legacy.py 开发
- 新功能必须通过 AuditOrchestrator 接入 /scan 入口

【测试要求】
- 运行 python governance/architecture_guard.py
- 运行 python -m pytest tests/test_<module>.py -v
```

---

## 如何避免修改公共契约

### 公共契约文件清单

```
audit_core/models.py
governance/module_boundaries.yaml
governance/public_contracts.yaml
contracts/*.schema.json
ARCHITECTURE.md
AGENTS.md (根目录)
```

### 如果需要修改公共契约

1. **不要直接修改**
2. 在群里发起讨论
3. 说明修改原因和影响
4. 等待所有成员同意
5. 由 Core Orchestrator 负责人统一修改

### 使用 Codex / Trae 时的注意事项

```
❌ 错误 Prompt：
"请帮我给 RawFinding 添加一个新字段 xxx"

✅ 正确 Prompt：
"我需要在 RawFinding 中存储 xxx 信息，有什么办法可以在不修改模型的前提下实现？"
```

---

## 如何提交 PR

### PR 流程

1. **创建分支**
   ```bash
   git checkout -b feature/<module>-<description>
   ```

2. **开发功能**
   - 按照任务模板开发
   - 遵守模块边界

3. **运行测试**
   ```bash
   # 必须运行的测试
   python governance/architecture_guard.py
   python -m pytest tests/contracts/ -v
   python -m pytest tests/test_<your_module>/ -v
   ```

4. **填写 PR 描述**
   ```markdown
   ## 变更摘要
   <!-- 简要描述 -->

   ## 变更范围
   - 修改文件1
   - 修改文件2

   ## 测试情况
   - [x] 架构守卫检查通过
   - [x] 契约测试通过
   - [x] 单元测试通过

   ## 是否修改公共契约
   - [ ] 否
   ```

5. **请求审查**
   - @Core Orchestrator 负责人
   - 等待审查通过

### PR 审查标准

- [ ] 修改范围符合模块边界
- [ ] 没有修改公共契约（除非已讨论）
- [ ] 所有测试通过
- [ ] 文档已更新

---

## 如何跑测试

### 必须运行的测试

```bash
# 1. 架构守卫检查（所有人）
python governance/architecture_guard.py

# 2. 契约测试（所有人）
python -m pytest tests/contracts/ -v

# 3. 模块单元测试（各自）
python -m pytest tests/test_<your_module>/ -v

# 4. 集成测试（修改 orchestrator 时）
python -m pytest tests/test_integration.py -v
```

### 测试失败怎么办

1. **架构守卫失败**
   - 检查是否有禁止的导入
   - 检查是否在错误的位置实现了功能

2. **契约测试失败**
   - 检查数据模型是否可序列化
   - 检查 /scan 返回字段是否完整

3. **单元测试失败**
   - 修复代码逻辑
   - 更新测试用例

---

## 如何处理跨模块改动

### 场景 1: 需要其他模块提供接口

1. 创建 Issue 描述需求
2. @相关模块负责人
3. 讨论接口设计
4. 等待接口实现
5. 使用新接口

### 场景 2: 发现其他模块 Bug

1. 不要直接修改
2. 创建 Issue 报告问题
3. @相关负责人
4. 等待修复

### 场景 3: 需要修改公共契约

1. 在群里发起讨论
2. 说明修改原因和影响范围
3. 所有成员同意
4. 由 Core Orchestrator 统一修改
5. 全员同步更新

---

## 如何维护 AGENTS.md 和 ARCHITECTURE.md

### AGENTS.md 维护

**根目录 AGENTS.md**
- 维护者：Core Orchestrator
- 更新时机：架构规则变化时

**模块 AGENTS.md**
- 维护者：各模块负责人
- 更新时机：模块行为变化时

**更新内容**
- 模块职责变化
- 输入输出变化
- 禁止行为更新

### ARCHITECTURE.md 维护

- 维护者：Core Orchestrator
- 更新时机：架构变化时

**更新内容**
- 新增模块
- 数据流变化
- 接口变化

### 使用 Codex / Trae 更新文档

```
请帮我更新 <文件>，添加以下内容：

【变更说明】
...

【需要更新的章节】
- 章节1：...
- 章节2：...

【约束】
- 保持原有格式
- 使用中文
- 添加修改记录
```

---

## 常见问题 FAQ

### Q: Codex / Trae 修改了不该修改的文件怎么办？

A:
1. 检查修改内容
2. 如果是不该修改的文件，撤销更改
3. 重新 Prompt，明确指定修改范围

### Q: 如何确保 Codex / Trae 遵守模块边界？

A:
1. 在 Prompt 中明确指定模块边界
2. 明确禁止基于旧入口开发（main.py, analysis_engine.py, legacy.py）
3. 强调新功能必须通过 AuditOrchestrator 接入
4. 使用架构守卫检查
5. 审查生成的代码

### Q: 测试不通过但代码看起来没问题？

A:
1. 检查是否修改了公共契约
2. 检查是否有禁止的导入
3. 检查数据模型是否可序列化

### Q: 紧急修复需要跳过流程吗？

A:
- 紧急 Bug 修复可以跳过部分流程
- 在 PR 中标记 "紧急修复"
- 立即通知相关成员
- 事后补充测试

---

## 快速参考

### 常用命令

```bash
# 架构守卫
python governance/architecture_guard.py

# 契约测试
python -m pytest tests/contracts/ -v

# 单元测试
python -m pytest tests/test_<module>/ -v

# 端到端测试
python -c "from audit_core.orchestrator import AuditOrchestrator; o = AuditOrchestrator(); print(o.scan_code('def test(): pass', 'python'))"
```

### 关键文件位置

```
AGENTS.md                    # 根目录治理规范
ARCHITECTURE.md              # 架构文档
TASKS/                       # 任务模板
governance/                  # 架构治理
contracts/                   # JSON Schema
tests/contracts/             # 契约测试
```

### 联系人

- **架构问题**: @Core Orchestrator 负责人
- **契约变更**: 全员讨论
- **跨模块冲突**: @Core Orchestrator 协调

---

## 最佳实践

### 1. 小步快跑
- 每次修改范围要小
- 频繁提交，频繁测试

### 2. 测试先行
- 写代码前先写测试
- 确保测试覆盖新功能

### 3. 文档同步
- 代码和文档同步更新
- 不要留下过时的文档

### 4. 及时沟通
- 有问题及时在群里讨论
- 不要独自做重大决定

---

*最后更新: 2025-05-30*
*版本: v1.0*
