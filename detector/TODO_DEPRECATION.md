# TODO: detector/ 模块删除计划

## 当前状态

`detector/` 模块包含旧的检测引擎（AST、Regex、Taint、Plugin）和内置检测器。
其 Python 检测能力已通过 `analyzers/python/PythonAnalyzer` 迁移到新的 analyzer 架构中。

`PythonAnalyzer` 直接 import 并委托给 `detector/` 的引擎，因此 **目前还不能删除 `detector/`**。

## 删除前置条件

以下条件全部满足后，可以安全删除 `detector/` 目录：

### 必须条件 (MUST)

1. **`analyzers/python/` 不再 import `detector/` 的任何模块**
   - AST/Regex/Taint 引擎代码已复制或重写到 `analyzers/python/engines/`
   - 规则加载逻辑已迁移到 `analyzers/python/core/rule_loader.py`
   - 数据模型 (`Finding`, `Rule`, `TaintFinding` 等) 已迁移到 `analyzers/python/core/models.py`
   - AST 工具函数已迁移到 `analyzers/python/core/ast_utils.py`

2. **`LegacyAnalyzerAdapter` 已从 registry 中移除或标记为 deprecated**
   - `audit_core/registry.py` 的 `build_default_registry()` 不再注册 `LegacyAnalyzerAdapter`
   - 或 `LegacyAnalyzerAdapter` 已改为使用 `analyzers/python/` 而非 `detector/`

3. **所有现有测试通过**
   - `python -m pytest tests/ -v` 全部通过
   - `python governance/architecture_guard.py` 全部检查通过

4. **多语言检测能力已迁移**
   - `detector/plugins/multilang.py` 的功能已迁移到对应语言 analyzer
   - `detector/plugins/ml_detection.py` 的功能已迁移或确认不需要

### 建议条件 (SHOULD)

5. **Plugin 机制已迁移**
   - `detector/engines/plugin_engine.py` 的扩展机制已迁移到 `analyzers/`
   - 或确认不再需要动态插件加载

6. **`detector/vuln_detector.py` 的 10 个内置检测器已被完全替代**
   - 确认 AST YAML 规则 + Taint 规则覆盖了所有 10 个内置检测器的功能
   - `detect_privilege_escalation` 的路由解析功能已迁移

7. **Tree-sitter 检测器已迁移**
   - `detector/tree_sitter_detectors.py` (JS/TS)
   - `detector/java_detector.py`
   - `detector/c_detector.py`
   - 这些检测器应迁移到对应的 `analyzers/javascript/`、`analyzers/java/`、`analyzers/c_cpp/`

## 迁移进度

| 组件 | 状态 | 说明 |
|------|------|------|
| `analyzers/python/PythonAnalyzer` | ✅ 已创建 | 委托给 detector 引擎，输出 RawFinding |
| Registry 优先级 | ✅ 已调整 | PythonAnalyzer 在 LegacyAnalyzerAdapter 之前注册 |
| LegacyAnalyzerAdapter | ⚠️ 保留为 fallback | 短期保留，待验证后移除 |
| AST 引擎代码迁移 | ❌ 待完成 | 当前仍 import detector.engines.ast_rule_engine |
| Regex 引擎代码迁移 | ❌ 待完成 | 当前仍 import detector.engines.regex_rule_engine |
| Taint 引擎代码迁移 | ❌ 待完成 | 当前仍 import detector.engines.taint_engine |
| 规则文件迁移 | ❌ 待完成 | 当前仍引用 detector/rules/ 下的 YAML |
| 数据模型迁移 | ❌ 待完成 | 当前仍引用 detector.core.models |
| Plugin 引擎迁移 | ❌ 待完成 | |
| 内置检测器废弃 | ❌ 待完成 | vuln_detector.py 10 个函数 |
| Tree-sitter 检测器迁移 | ❌ 待完成 | JS/Java/C 检测器 |
| ML 检测迁移 | ❌ 待评估 | ml_detection.py |

## 相关文件

- 新 analyzer: `analyzers/python/python_analyzer.py`
- Registry: `audit_core/registry.py`
- Legacy adapter: `analyzers/legacy_adapter.py`
- 旧引擎: `detector/engines/`
- 旧规则: `detector/rules/`
- 旧检测器: `detector/vuln_detector.py`
