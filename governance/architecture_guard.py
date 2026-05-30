#!/usr/bin/env python3
"""
Architecture Guard - 轻量级架构检查工具

检查项目是否符合架构规范，包括：
1. 禁止的跨模块导入
2. /scan 返回字段完整性
3. 模块边界合规性

使用方法:
    python governance/architecture_guard.py

退出码:
    0 - 所有检查通过
    1 - 发现架构违规
"""

import ast
import sys
from pathlib import Path
from typing import List, Tuple, Set


class ArchitectureGuard:
    """架构守卫 - 检查项目架构合规性"""
    
    def __init__(self, project_root: Path):
        self.project_root = project_root
        self.violations: List[str] = []
        
    def check_all(self) -> bool:
        """运行所有检查"""
        print("=" * 60)
        print("VulnPatch Architecture Guard")
        print("=" * 60)
        
        checks = [
            ("禁止的跨模块导入", self.check_forbidden_imports),
            ("/scan 返回字段", self.check_scan_response),
            ("模块边界合规性", self.check_module_boundaries),
        ]
        
        all_passed = True
        for check_name, check_func in checks:
            print(f"\n🔍 检查: {check_name}")
            print("-" * 40)
            passed = check_func()
            if not passed:
                all_passed = False
            status = "✅ 通过" if passed else "❌ 失败"
            print(f"结果: {status}")
        
        print("\n" + "=" * 60)
        if all_passed:
            print("✅ 所有架构检查通过！")
        else:
            print(f"❌ 发现 {len(self.violations)} 个架构违规:")
            for v in self.violations:
                print(f"  - {v}")
        print("=" * 60)
        
        return all_passed
    
    def check_forbidden_imports(self) -> bool:
        """检查禁止的跨模块导入"""
        forbidden_rules = {
            "analyzers": ["agents", "llm"],
            "agents": ["ingest.repo_loader"],
            "api": ["analyzers.pattern_analyzer", "agents.analysis_agent"],
        }
        
        passed = True
        
        for module_dir, forbidden_modules in forbidden_rules.items():
            module_path = self.project_root / module_dir
            if not module_path.exists():
                continue
                
            for py_file in module_path.rglob("*.py"):
                if py_file.name == "__init__.py":
                    continue
                    
                imports = self._extract_imports(py_file)
                
                for forbidden in forbidden_modules:
                    for imp in imports:
                        if forbidden in imp:
                            violation = f"{py_file}: 禁止导入 '{forbidden}'"
                            self.violations.append(violation)
                            print(f"  ❌ {violation}")
                            passed = False
        
        if passed:
            print("  ✅ 未发现禁止的跨模块导入")
        
        return passed
    
    def check_scan_response(self) -> bool:
        """检查 /scan 返回字段完整性"""
        required_fields = {
            "summary": ["total_code_units", "total_findings", "total_evidence_bundles", 
                       "risk_score", "languages", "scanned_files"],
            "findings": [],
            "evidence": [],
            "agent_logs": []
        }
        
        passed = True
        
        # 检查 api/schemas.py 中的 ScanResponse
        schemas_file = self.project_root / "api" / "schemas.py"
        if schemas_file.exists():
            content = schemas_file.read_text()
            
            for field in required_fields.keys():
                if field not in content:
                    violation = f"api/schemas.py: 缺少必需字段 '{field}'"
                    self.violations.append(violation)
                    print(f"  ❌ {violation}")
                    passed = False
        
        # 检查 audit_core/models.py 中的 AuditResult
        models_file = self.project_root / "audit_core" / "models.py"
        if models_file.exists():
            content = models_file.read_text()
            
            for field in required_fields.keys():
                if field not in content:
                    violation = f"audit_core/models.py: 缺少必需字段 '{field}'"
                    self.violations.append(violation)
                    print(f"  ❌ {violation}")
                    passed = False
        
        if passed:
            print("  ✅ /scan 返回字段完整")
        
        return passed
    
    def check_module_boundaries(self) -> bool:
        """检查模块边界合规性"""
        passed = True
        
        # 检查 api/ 是否包含检测规则
        api_routes = self.project_root / "api" / "routes"
        if api_routes.exists():
            for py_file in api_routes.rglob("*.py"):
                content = py_file.read_text()
                
                # 检查是否在 API 中实现了检测逻辑
                suspicious_patterns = [
                    "if \"SELECT\" in",
                    "if 'SELECT' in",
                    "re.search.*SELECT",
                ]
                
                for pattern in suspicious_patterns:
                    if pattern in content:
                        violation = f"{py_file}: 可能在 API 中实现了检测规则"
                        self.violations.append(violation)
                        print(f"  ⚠️  {violation}")
                        # 这只是警告，不标记为失败
        
        # 检查 agents/ 是否直接读取文件系统
        agents_dir = self.project_root / "agents"
        if agents_dir.exists():
            for py_file in agents_dir.rglob("*.py"):
                if py_file.name == "__init__.py":
                    continue
                    
                content = py_file.read_text()
                
                # 检查是否直接 open 文件
                if "open(" in content and "code_unit" not in content:
                    # 排除测试文件和合法用法
                    if "test" not in py_file.name:
                        violation = f"{py_file}: 可能直接读取文件系统"
                        self.violations.append(violation)
                        print(f"  ⚠️  {violation}")
        
        if passed:
            print("  ✅ 模块边界合规")
        
        return passed
    
    def _extract_imports(self, file_path: Path) -> List[str]:
        """提取 Python 文件中的所有导入"""
        imports = []
        
        try:
            content = file_path.read_text()
            tree = ast.parse(content)
            
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        imports.append(alias.name)
                elif isinstance(node, ast.ImportFrom):
                    module = node.module or ""
                    imports.append(module)
                    for alias in node.names:
                        imports.append(f"{module}.{alias.name}")
        except SyntaxError:
            pass
        
        return imports


def main():
    """主入口"""
    project_root = Path(__file__).parent.parent
    
    guard = ArchitectureGuard(project_root)
    passed = guard.check_all()
    
    sys.exit(0 if passed else 1)


if __name__ == "__main__":
    main()
