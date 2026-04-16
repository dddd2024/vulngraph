from __future__ import annotations

import difflib
import json
import os
import re
import shutil
import subprocess
import tempfile
import time
import urllib.error
import urllib.request
import zipfile
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from detector.vuln_detector import (
    detect_path_traversal,
    detect_privilege_escalation,
    detect_sql_injection,
)

try:
    from openai import OpenAI
except Exception:  # pragma: no cover
    OpenAI = None  # type: ignore[assignment]


def _collect_py_files(root: Path) -> list[Path]:
    return [p for p in root.rglob("*.py") if p.is_file()]


def _to_diff(original: str, updated: str, file_path: str) -> str:
    return "".join(
        difflib.unified_diff(
            original.splitlines(keepends=True),
            updated.splitlines(keepends=True),
            fromfile=f"a/{file_path}",
            tofile=f"b/{file_path}",
        )
    )


def _rule_patch_sql_injection(source: str, var_name: str = "name") -> tuple[str, str]:
    updated = source
    updated = re.sub(
        r'sql\s*=\s*"SELECT \* FROM users WHERE name=\'"\s*\+\s*(\w+)\s*\+\s*"\'"',
        'sql = "SELECT * FROM users WHERE name=?"',
        updated,
    )
    updated = re.sub(
        r"(\w+)\s*=\s*conn\.execute\(\s*sql\s*\)",
        rf"\1 = conn.execute(sql, ({var_name},))",
        updated,
    )
    reason = "将字符串拼接 SQL 改为参数化查询，阻断 SQL 注入。"
    return updated, reason


def _rule_patch_path_traversal(source: str) -> tuple[str, str]:
    pattern = "with open(path, \"r\", encoding=\"utf-8\") as f:"
    if pattern in source:
        updated = source.replace(
            pattern,
            "base = Path(\".\").resolve()\n"
            "    target = (base / path).resolve()\n"
            "    if base not in target.parents and target != base:\n"
            "        raise ValueError(\"非法路径\")\n"
            "    with open(target, \"r\", encoding=\"utf-8\") as f:",
        )
        if "from pathlib import Path" not in updated:
            updated = "from pathlib import Path\n\n" + updated
        return updated, "增加路径规范化与目录边界校验，阻止路径穿越。"
    return source, "建议对 open(path) 增加 realpath 校验和白名单目录限制。"


def _rule_patch_privilege(source: str) -> tuple[str, str]:
    if "@admin_required" in source:
        return source, "已存在权限注解。"
    updated = source
    updated = re.sub(
        r"(@app\.route\('/admin[^']*'\)\n)(def\s+\w+\()",
        r"\1@admin_required\n\2",
        updated,
    )
    if "from auth import admin_required" not in updated:
        lines = updated.splitlines()
        insert_at = 0
        for i, line in enumerate(lines):
            if line.startswith("from ") or line.startswith("import "):
                insert_at = i + 1
        lines.insert(insert_at, "from auth import admin_required")
        updated = "\n".join(lines) + ("\n" if source.endswith("\n") else "")
    return updated, "为管理员路由增加 @admin_required 权限校验。"


def _line_of(source: str, index: int) -> int:
    return source[:index].count("\n") + 1


def _pattern_engine_findings(file_path: Path, source: str) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []

    sql_patterns = [
        re.finditer(r"execute\(\s*f[\"']SELECT .*?\{.+?\}.*?[\"']\s*\)", source, re.DOTALL),
        re.finditer(r"execute\(\s*[\"']SELECT .*?[\"']\s*%\s*.+\)", source, re.DOTALL),
    ]
    for matches in sql_patterns:
        for m in matches:
            findings.append(
                {
                    "type": "SQL Injection",
                    "file": str(file_path),
                    "line": _line_of(source, m.start()),
                    "severity": "ERROR",
                    "engine": "pattern",
                }
            )

    for m in re.finditer(r"open\(\s*(request\.(args|form)\.get\(.+?\)|path)\s*[,\)]", source):
        findings.append(
            {
                "type": "Path Traversal",
                "file": str(file_path),
                "line": _line_of(source, m.start()),
                "severity": "ERROR",
                "engine": "pattern",
            }
        )

    for m in re.finditer(r"@app\.route\([\"']/admin[^\"']*[\"']\)", source):
        block_start = m.start()
        line_start = source.rfind("\n", 0, block_start)
        window = source[max(0, line_start - 200) : m.end() + 200]
        if "@admin_required" not in window and "@login_required" not in window:
            findings.append(
                {
                    "type": "Privilege Escalation",
                    "file": str(file_path),
                    "line": _line_of(source, m.start()),
                    "severity": "ERROR",
                    "engine": "pattern",
                }
            )

    return findings


def _github_owner_repo(repo_url: str) -> tuple[str, str] | None:
    parsed = urlparse(repo_url)
    if parsed.netloc.lower() != "github.com":
        return None
    parts = [p for p in parsed.path.strip("/").split("/") if p]
    if len(parts) < 2:
        return None
    owner = parts[0]
    repo = parts[1].removesuffix(".git")
    return owner, repo


def _clone_with_retry(repo_url: str, repo_root: Path) -> tuple[bool, str]:
    candidates = [repo_url.rstrip("/")]
    if not candidates[0].endswith(".git"):
        candidates.append(candidates[0] + ".git")
    errors: list[str] = []

    for round_idx in range(1, 4):
        for url in candidates:
            proc = subprocess.run(
                ["git", "clone", "--depth", "1", url, str(repo_root)],
                capture_output=True,
                text=True,
                timeout=70,
            )
            if proc.returncode == 0:
                return True, f"git clone 成功：{url}"
            detail = (proc.stderr or proc.stdout or "").strip()
            errors.append(f"[第{round_idx}轮] {url} -> {detail}")
            if repo_root.exists():
                shutil.rmtree(repo_root, ignore_errors=True)
        time.sleep(1.2 * round_idx)

    return False, "\n".join(errors)


def _download_zip_fallback(repo_url: str, repo_root: Path) -> tuple[bool, str]:
    owner_repo = _github_owner_repo(repo_url)
    if not owner_repo:
        return False, "仅 github.com 仓库支持 ZIP 回退下载。"
    owner, repo = owner_repo
    branches = ["main", "master"]

    for branch in branches:
        zip_url = f"https://codeload.github.com/{owner}/{repo}/zip/refs/heads/{branch}"
        try:
            with urllib.request.urlopen(zip_url, timeout=35) as resp:
                data = resp.read()
            zip_path = repo_root.parent / f"{repo}-{branch}.zip"
            zip_path.write_bytes(data)
            with zipfile.ZipFile(zip_path, "r") as zf:
                zf.extractall(repo_root.parent)
            extracted = repo_root.parent / f"{repo}-{branch}"
            if repo_root.exists():
                shutil.rmtree(repo_root, ignore_errors=True)
            shutil.move(str(extracted), str(repo_root))
            zip_path.unlink(missing_ok=True)
            return True, f"ZIP 回退下载成功：{zip_url}"
        except Exception:
            continue

    return False, "ZIP 回退下载失败（main/master 均不可用）。"


def _dedup_findings(raw_findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    merged: dict[tuple[str, str, int], dict[str, Any]] = {}
    for f in raw_findings:
        key = (f["type"], f["file"], int(f.get("line", 0)))
        engine = f.get("engine", "ast")
        if key not in merged:
            item = dict(f)
            item["engines"] = [engine]
            merged[key] = item
        else:
            engines = merged[key]["engines"]
            if engine not in engines:
                engines.append(engine)
    return list(merged.values())


def _call_cloud_ai(prompt: str) -> str:
    # 优先使用 Copilot CLI（与你当前终端同模型链路）
    cp = subprocess.run(
        ["gh", "copilot", "-p", prompt],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="ignore",
    )
    if cp.returncode == 0 and cp.stdout.strip():
        lines = []
        for line in cp.stdout.splitlines():
            line = line.rstrip()
            if not line:
                continue
            if line.startswith(("Changes", "Requests", "Tokens")):
                continue
            lines.append(line)
        cleaned = "\n".join(lines).strip()
        if cleaned:
            return cleaned

    # 次级回退：OpenAI API（兼容旧配置）
    if OpenAI is None:
        raise RuntimeError(f"Copilot CLI 调用失败：{cp.stderr.strip() or cp.stdout.strip()}")
    if not os.getenv("OPENAI_API_KEY"):
        raise RuntimeError(
            "Copilot CLI 调用失败，且 OPENAI_API_KEY 未配置，无法回退到 OpenAI。"
        )
    client = OpenAI()
    resp = client.chat.completions.create(
        model=os.getenv("OPENAI_MODEL", "gpt-4.1"),
        messages=[{"role": "user", "content": prompt}],
    )
    return (resp.choices[0].message.content or "").strip()


def _call_local_ai(prompt: str) -> str:
    url = os.getenv("LOCAL_LLM_URL", "http://127.0.0.1:11434/api/generate")
    body = json.dumps(
        {
            "model": os.getenv("LOCAL_LLM_MODEL", "qwen2.5-coder:7b"),
            "prompt": prompt,
            "stream": False,
        }
    ).encode("utf-8")
    req = urllib.request.Request(
        url, data=body, headers={"Content-Type": "application/json"}, method="POST"
    )
    with urllib.request.urlopen(req, timeout=25) as resp:
        payload = json.loads(resp.read().decode("utf-8"))
    return str(payload.get("response", "")).strip()


def generate_ai_text(ai_mode: str, prompt: str) -> str:
    if ai_mode == "cloud":
        return _call_cloud_ai(prompt)
    if ai_mode == "local":
        return _call_local_ai(prompt)
    raise ValueError(f"unsupported ai_mode for text generation: {ai_mode}")


def _patch_with_ai(
    ai_mode: str,
    vuln: dict[str, Any],
    original: str,
    rule_diff: str,
    rule_reason: str,
) -> tuple[str, str, str]:
    if ai_mode == "rule":
        return rule_diff, rule_reason, "rule"

    prompt = (
        "你是代码安全修复助手。请针对以下漏洞给出简短补丁（尽量 unified diff）。\n\n"
        f"漏洞类型: {vuln['type']}\n"
        f"文件: {vuln['file']}:{vuln['line']}\n"
        f"原始代码片段:\n{original[:1200]}\n\n"
        f"规则补丁候选:\n{rule_diff[:1200]}\n"
    )
    try:
        if ai_mode in ("cloud", "local"):
            patch_text = generate_ai_text(ai_mode, prompt)
            patch_reason = "云端 AI 生成" if ai_mode == "cloud" else "本地 AI 生成"
            return patch_text, patch_reason, ai_mode
    except (RuntimeError, urllib.error.URLError, TimeoutError) as exc:
        return rule_diff, f"{rule_reason}（AI 不可用，已回退规则补丁：{exc}）", "rule-fallback"
    return rule_diff, rule_reason, "rule"


def _build_finding_output(
    vuln: dict[str, Any], file_path: Path, root: Path, ai_mode: str
) -> dict[str, Any]:
    original = file_path.read_text(encoding="utf-8", errors="ignore")
    relative = str(file_path.relative_to(root)).replace("\\", "/")

    if vuln["type"] == "SQL Injection":
        updated, rule_reason = _rule_patch_sql_injection(original)
    elif vuln["type"] == "Path Traversal":
        updated, rule_reason = _rule_patch_path_traversal(original)
    elif vuln["type"] == "Privilege Escalation":
        updated, rule_reason = _rule_patch_privilege(original)
    else:
        updated, rule_reason = original, "未命中规则补丁。"

    rule_diff = _to_diff(original, updated, relative)
    if not rule_diff:
        rule_diff = f"# 未自动生成差异，建议手工修复：{rule_reason}"

    patch_text, patch_reason, patch_mode = _patch_with_ai(
        ai_mode, vuln, original, rule_diff, rule_reason
    )
    taxonomy = {
        "SQL Injection": {"cwe": "CWE-89", "confidence": "high"},
        "Path Traversal": {"cwe": "CWE-22", "confidence": "medium"},
        "Privilege Escalation": {"cwe": "CWE-269", "confidence": "medium"},
    }
    meta = taxonomy.get(vuln["type"], {"cwe": "CWE-Other", "confidence": "low"})
    severity = vuln.get("severity", "ERROR")
    score_base = 90 if severity == "ERROR" else 70
    if meta["confidence"] == "medium":
        score_base -= 15
    if meta["confidence"] == "low":
        score_base -= 30
    if len(vuln.get("engines", [])) > 1:
        score_base += 5
    return {
        "type": vuln["type"],
        "severity": severity,
        "cwe": meta["cwe"],
        "confidence": meta["confidence"],
        "risk_score": max(0, min(score_base, 100)),
        "engines": vuln.get("engines", ["ast"]),
        "file": relative,
        "line": vuln.get("line", 0),
        "patch_mode": patch_mode,
        "patch_reason": patch_reason,
        "patch": patch_text,
    }


def _analyze_repo(repo_root: Path, ai_mode: str) -> dict[str, Any]:
    findings: list[dict[str, Any]] = []
    skipped: list[str] = []
    for py_file in _collect_py_files(repo_root):
        try:
            ast_findings = []
            ast_findings.extend(detect_sql_injection(str(py_file)))
            ast_findings.extend(detect_path_traversal(str(py_file)))
            ast_findings.extend(detect_privilege_escalation(str(py_file)))
            for f in ast_findings:
                f["engine"] = "ast"
            findings.extend(ast_findings)

            source = py_file.read_text(encoding="utf-8", errors="ignore")
            findings.extend(_pattern_engine_findings(py_file, source))
        except Exception:
            skipped.append(str(py_file.relative_to(repo_root)).replace("\\", "/"))

    findings = _dedup_findings(findings)
    out_findings = [
        _build_finding_output(v, Path(v["file"]), repo_root, ai_mode) for v in findings
    ]
    return {
        "vulnerabilities": out_findings,
        "count": len(out_findings),
        "ai_mode": ai_mode,
        "skipped_files": skipped,
    }


def analyze_input(
    input_type: str,
    ai_mode: str = "rule",
    code: str | None = None,
    repo_url: str | None = None,
    progress_callback: Any | None = None,
) -> dict[str, Any]:
    def emit(stage: str, progress: int, message: str) -> None:
        if callable(progress_callback):
            progress_callback(stage, progress, message)

    with tempfile.TemporaryDirectory(prefix="security_input_") as tmp:
        tmp_root = Path(tmp)
        repo_root = tmp_root / "repo"
        repo_root.mkdir(parents=True, exist_ok=True)
        emit("prepare", 5, "初始化临时分析目录")

        if input_type == "code":
            if not code or not code.strip():
                raise ValueError("代码输入不能为空。")
            (repo_root / "input.py").write_text(code, encoding="utf-8")
            emit("prepare", 15, "已写入代码片段")
        elif input_type == "github":
            if not repo_url or not repo_url.strip():
                raise ValueError("仓库 URL 不能为空。")
            shutil.rmtree(repo_root)
            emit("prepare", 15, "开始克隆 GitHub 仓库")
            try:
                ok, detail = _clone_with_retry(repo_url.strip(), repo_root)
            except subprocess.TimeoutExpired as exc:
                raise RuntimeError(
                    "克隆仓库超时：当前网络无法在限定时间内连接或拉取 GitHub。"
                ) from exc

            if not ok:
                emit("prepare", 28, "git clone 失败，尝试 ZIP 下载回退")
                zip_ok, zip_detail = _download_zip_fallback(repo_url.strip(), repo_root)
                if not zip_ok:
                    raise RuntimeError(
                        "克隆仓库失败：网络连接 GitHub 失败（可能是网络受限/被重置）。\n"
                        f"{detail}\n{zip_detail}"
                    )
                emit("prepare", 35, zip_detail)
            else:
                emit("prepare", 35, "仓库克隆完成")
        else:
            raise ValueError("input_type 仅支持 code 或 github。")

        emit("detect", 55, "开始漏洞检测")
        analysis = _analyze_repo(repo_root, ai_mode=ai_mode)
        emit("patch", 85, "漏洞检测完成，正在整理补丁输出")
        analysis["input_type"] = input_type
        if input_type == "github":
            analysis["repo_url"] = repo_url
        emit("done", 100, "分析完成")
        return analysis

