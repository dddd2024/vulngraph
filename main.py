import json
import subprocess
import sys
from pathlib import Path
from typing import Any

from detector.impact_analyzer import find_impacted_modules
from detector.vuln_detector import detect_all
from parser.call_graph import build_call_graph, export_edges
from parser.repo_scanner import scan_repo
from patch.apply_patcher import apply_patch_text
from patch.generate_patch import generate_patch
from rag.embed import build_vector_store
from rag.prompt_builder import build_prompt


def run_pipeline(project_root: str = ".") -> dict[str, Any]:
    root = Path(project_root).resolve()
    files = scan_repo(str(root / "repo"))
    graph = build_call_graph(str(root / "repo"))
    findings = detect_all(str(root / "repo"))
    if not findings:
        raise RuntimeError("No vulnerabilities detected.")

    target = next((f for f in findings if f["type"] == "SQL Injection"), findings[0])
    impact = find_impacted_modules(graph, target.get("symbol", "search_user"))
    store = build_vector_store(files)
    context_docs = store.similarity_search(
        f'{target["type"]} {target.get("symbol", "")} {target["file"]}'
    )
    context = "\n\n".join(f"[{doc.source}]\n{doc.text}" for doc in context_docs)
    prompt = build_prompt(target, context, impact)
    generated = generate_patch(target, prompt, str(root))
    patch_file = apply_patch_text(str(root), generated["patch"])

    tests_dir = root / "tests"
    tests_dir.mkdir(exist_ok=True)
    (tests_dir / "test_fix.py").write_text(generated["test"], encoding="utf-8")

    pytest_proc = subprocess.run(
        [sys.executable, "-m", "pytest", "tests/test_fix.py", "-q"],
        cwd=str(root),
        capture_output=True,
        text=True,
    )

    result = {
        "target": target,
        "impact": impact,
        "patch_file": str(patch_file),
        "pytest_ok": pytest_proc.returncode == 0,
        "pytest_stdout": pytest_proc.stdout,
        "pytest_stderr": pytest_proc.stderr,
        "graph_edges": export_edges(graph),
        "findings": findings,
    }
    (root / "pipeline_result.json").write_text(
        json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    return result


if __name__ == "__main__":
    output = run_pipeline(".")
    print(json.dumps(output, ensure_ascii=False, indent=2))

