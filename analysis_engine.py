from __future__ import annotations

import re
import shutil
import subprocess
import tempfile
import time
import urllib.request
import zipfile
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from detector.core.language_router import LanguageRouter

SUPPORTED_LANGUAGES = ["zh-CN", "en-US"]

VULNERABILITY_TYPE_ZH = {
    "SQL Injection": "SQL 注入",
    "Path Traversal": "路径穿越",
    "Privilege Escalation": "权限提升",
    "Dangerous Code Execution": "危险代码执行",
    "Command Injection": "命令注入",
    "Unsafe Deserialization": "不安全反序列化",
    "Hardcoded Secret": "硬编码密钥",
    "Weak Cryptography": "弱加密",
    "Debug Mode Enabled": "调试模式",
    "Insecure TLS Verification": "不安全 TLS 验证",
    # 多语言检测器漏洞类型
    "Buffer Overflow": "缓冲区溢出",
    "Format String Vulnerability": "格式化字符串漏洞",
    "Memory Leak": "内存泄漏",
    "Cross-Site Scripting (XSS)": "跨站脚本攻击 (XSS)",
    "Code Injection / Eval Usage": "代码注入 / Eval 使用",
    "Insecure Deserialization": "不安全反序列化",
    "XML External Entity (XXE)": "XML 外部实体攻击 (XXE)",
    "LDAP Injection": "LDAP 注入",
    "Log Injection": "日志注入",
    "Insecure Random Number": "不安全随机数",
    "Race Condition (TOCTOU)": "竞态条件 (TOCTOU)",
    "Null Pointer Dereference": "空指针解引用",
    "Integer Overflow": "整数溢出",
    "SSRF": "服务器端请求伪造",
    "Hardcoded Credentials": "硬编码凭证",
}

SEVERITY_ZH = {
    "ERROR": "严重",
    "WARN": "警告",
    "WARNING": "警告",
    "INFO": "信息",
    "UNKNOWN": "未知",
}

CONFIDENCE_ZH = {
    "high": "高",
    "medium": "中",
    "low": "低",
}

ENGINE_ZH = {
    "ast": "AST 静态分析",
    "pattern": "模式匹配",
    "plugin": "插件检测",
    "regex": "正则匹配",
    "tree-sitter": "Tree-sitter 分析",
    "ml": "深度学习检测",
    "ml-fallback": "ML 模式检测",
    "taint": "污点流分析",
}


# 多语言扫描支持的文件扩展名
_CODE_EXTENSIONS: set[str] = {
    ".py", ".js", ".jsx", ".ts", ".tsx", ".java",
    ".go", ".php", ".c", ".h", ".cpp", ".cc", ".cxx", ".hpp", ".rs",
}

# 扫描时忽略的目录名
_IGNORED_DIRS: set[str] = {
    ".git", "node_modules", "dist", "build",
    "__pycache__", ".venv", "venv", "target", ".idea",
    ".vscode", ".settings", "vendor", "third_party",
}


def _collect_code_files(root: Path) -> list[Path]:
    """收集仓库中所有支持语言的代码文件，忽略常见非代码目录."""
    results: list[Path] = []
    for p in root.rglob("*"):
        if not p.is_file():
            continue
        if p.suffix.lower() not in _CODE_EXTENSIONS:
            continue
        # 检查路径中是否包含忽略目录
        if any(part in _IGNORED_DIRS for part in p.parts):
            continue
        results.append(p)
    return results


# 语言到文件名的映射
_LANGUAGE_TO_FILENAME: dict[str, str] = {
    "python": "input.py",
    "javascript": "input.js",
    "typescript": "input.ts",
    "java": "Vulnerable.java",
    "c": "input.c",
    "cpp": "input.cpp",
    "php": "input.php",
    "go": "input.go",
    "rust": "input.rs",
}


def _write_code_snippet(
    repo_root: Path, code: str, language_hint: str | None = None
) -> tuple[Path, str, dict[str, Any]]:
    """根据代码语言将代码片段写入对应文件.

    Args:
        repo_root: 临时目录根路径
        code: 代码内容
        language_hint: 用户指定的语言提示，None或"auto"表示自动检测

    Returns:
        (写入的文件路径, 检测到的语言, 诊断信息字典)
    """
    from parser.language_detector import detect_language

    diagnostic: dict[str, Any] = {
        "language_hint": language_hint,
        "auto_detected": False,
        "detected_language": None,
        "used_filename": "",
        "error": None,
    }

    # 确定语言
    detected_lang: str
    if language_hint and language_hint.lower() not in ("auto", ""):
        detected_lang = language_hint.lower()
        diagnostic["auto_detected"] = False
    else:
        detected_lang = detect_language(code, filename=None)
        diagnostic["auto_detected"] = True

    diagnostic["detected_language"] = detected_lang

    # 选择文件名
    filename = _LANGUAGE_TO_FILENAME.get(detected_lang)
    if not filename:
        # 未识别语言，使用默认文件名但记录
        filename = "input.txt"
        diagnostic["error"] = f"未识别的语言: {detected_lang}，使用默认文件名"

    diagnostic["used_filename"] = filename

    # 写入文件
    file_path = repo_root / filename
    file_path.write_text(code, encoding="utf-8")

    return file_path, detected_lang, diagnostic


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
            # 合并 metadata：如果新 finding 有 metadata 而旧的没有，则合并
            if "metadata" in f and "metadata" not in merged[key]:
                merged[key]["metadata"] = f["metadata"]
    return list(merged.values())


def _bilingual_pair(en_value: Any, zh_labels: dict[str, str]) -> dict[str, str]:
    en = str(en_value or "")
    return {"en": en, "zh": zh_labels.get(en, en)}


def _build_bilingual_finding(finding: dict[str, Any]) -> dict[str, Any]:
    engines = finding.get("engines", [])
    if not isinstance(engines, list):
        engines = [engines]
    return {
        "type": _bilingual_pair(finding.get("type"), VULNERABILITY_TYPE_ZH),
        "severity": _bilingual_pair(finding.get("severity"), SEVERITY_ZH),
        "confidence": _bilingual_pair(finding.get("confidence"), CONFIDENCE_ZH),
        "engines": [_bilingual_pair(engine, ENGINE_ZH) for engine in engines],
    }


def _analysis_error_reason(exc: Exception) -> tuple[str, str]:
    detail = str(exc).strip()
    if isinstance(exc, SyntaxError):
        location = ""
        if exc.lineno:
            location = f" line {exc.lineno}"
            if exc.offset:
                location += f", column {exc.offset}"
        en = f"Code parsing failed{location}. Please make sure the input is valid Python code."
        zh = "代码解析失败，请确认输入是合法 Python 代码。"
        if exc.lineno:
            zh = f"代码解析失败（第 {exc.lineno} 行），请确认输入是合法 Python 代码。"
        return en, zh

    error_name = type(exc).__name__
    if detail:
        return (
            f"File analysis failed: {error_name}: {detail}",
            f"文件分析失败：{error_name}: {detail}",
        )
    return (
        f"File analysis failed: {error_name}",
        f"文件分析失败：{error_name}",
    )


def _build_skipped_detail(file_path: Path, root: Path, detector: str, exc: Exception) -> dict[str, str]:
    reason_en, reason_zh = _analysis_error_reason(exc)
    return {
        "file": str(file_path.relative_to(root)).replace("\\", "/"),
        "detector": detector,
        "reason_en": reason_en,
        "reason_zh": reason_zh,
        "error_type": type(exc).__name__,
    }


def _display_vulnerability(finding: dict[str, Any]) -> dict[str, Any]:
    bilingual = finding.get("bilingual") or _build_bilingual_finding(finding)
    return {
        "文件": finding.get("file", ""),
        "行号": finding.get("line", 0),
        "语言": finding.get("language", "Python"),
        "漏洞类型": bilingual["type"]["zh"],
        "漏洞类型_en": bilingual["type"]["en"],
        "严重级别": bilingual["severity"]["zh"],
        "严重级别_en": bilingual["severity"]["en"],
        "CWE": finding.get("cwe", ""),
        "置信度": bilingual["confidence"]["zh"],
        "置信度_en": bilingual["confidence"]["en"],
        "风险分": finding.get("risk_score", 0),
        "检测引擎": [engine["zh"] for engine in bilingual.get("engines", [])],
        "检测引擎_en": [engine["en"] for engine in bilingual.get("engines", [])],
    }


def _build_display(
    *,
    vulnerabilities: list[dict[str, Any]],
    skipped_details: list[dict[str, str]],
) -> dict[str, Any]:
    count = len(vulnerabilities)
    skipped_display = [
        {
            "文件": item["file"],
            "检测器": item.get("detector", ""),
            "原因": item["reason_zh"],
            "原因_en": item["reason_en"],
        }
        for item in skipped_details
    ]

    if count > 0:
        message = f"检测到 {count} 个漏洞。"
    elif skipped_details:
        message = "未生成漏洞结果，部分文件分析失败，请查看跳过文件。"
    else:
        message = "未检测到漏洞。"

    return {
        "zh": {
            "summary": {
                "漏洞数量": count,
                "跳过文件数量": len(skipped_details),
            },
            "message": message,
            "vulnerabilities": [_display_vulnerability(item) for item in vulnerabilities],
            "skipped_files": skipped_display,
        }
    }


def _normalize_file_path(file_path: str | Path, root: Path) -> str:
    """将文件路径规范化为相对于 root 的相对路径，统一使用正斜杠.

    - 如果 file_path 是绝对路径且位于 root 下，转成相对 root 的路径
    - 如果 file_path 是绝对路径但不在 root 下，返回文件名
    - 如果 file_path 本来就是相对路径，保留原始相对路径层级
    """
    p = Path(file_path)

    # 如果本来就是相对路径，直接统一斜杠格式
    if not p.is_absolute():
        return str(p).replace("\\", "/")

    # 是绝对路径，尝试转为相对于 root 的路径
    try:
        rel = p.relative_to(root)
        return str(rel).replace("\\", "/")
    except ValueError:
        # 不在 root 下，返回文件名
        return str(Path(p.name)).replace("\\", "/")


def _build_finding_output(vuln: dict[str, Any], root: Path | None = None) -> dict[str, Any]:
    """构建漏洞检测结果输出（不含补丁相关字段）"""
    taxonomy = {
        "SQL Injection": {"cwe": "CWE-89", "confidence": "high"},
        "Path Traversal": {"cwe": "CWE-22", "confidence": "medium"},
        "Privilege Escalation": {"cwe": "CWE-269", "confidence": "medium"},
        "Dangerous Code Execution": {"cwe": "CWE-95", "confidence": "high"},
        "Command Injection": {"cwe": "CWE-78", "confidence": "high"},
        "Unsafe Deserialization": {"cwe": "CWE-502", "confidence": "high"},
        "Hardcoded Secret": {"cwe": "CWE-798", "confidence": "medium"},
        "Weak Cryptography": {"cwe": "CWE-327", "confidence": "medium"},
        "Debug Mode Enabled": {"cwe": "CWE-489", "confidence": "medium"},
        "Insecure TLS Verification": {"cwe": "CWE-295", "confidence": "medium"},
        # 多语言检测器漏洞类型
        "Buffer Overflow": {"cwe": "CWE-120", "confidence": "high"},
        "Format String Vulnerability": {"cwe": "CWE-134", "confidence": "high"},
        "Memory Leak": {"cwe": "CWE-401", "confidence": "medium"},
        "Cross-Site Scripting (XSS)": {"cwe": "CWE-79", "confidence": "high"},
        "Code Injection / Eval Usage": {"cwe": "CWE-94", "confidence": "high"},
        "XML External Entity (XXE)": {"cwe": "CWE-611", "confidence": "high"},
        "LDAP Injection": {"cwe": "CWE-90", "confidence": "high"},
        "Log Injection": {"cwe": "CWE-117", "confidence": "medium"},
        "Insecure Random Number": {"cwe": "CWE-338", "confidence": "medium"},
        "Race Condition (TOCTOU)": {"cwe": "CWE-362", "confidence": "medium"},
        "Null Pointer Dereference": {"cwe": "CWE-476", "confidence": "high"},
        "Integer Overflow": {"cwe": "CWE-190", "confidence": "medium"},
        "SSRF": {"cwe": "CWE-918", "confidence": "high"},
        "Hardcoded Credentials": {"cwe": "CWE-798", "confidence": "medium"},
    }
    meta = taxonomy.get(vuln["type"], {"cwe": "CWE-Other", "confidence": "low"})

    # 优先使用检测器原始值，taxonomy 仅作为默认值
    cwe = vuln.get("cwe") or meta["cwe"]
    confidence = vuln.get("confidence") or meta["confidence"]
    message = vuln.get("message") or vuln.get("detail") or ""

    severity = vuln.get("severity", "ERROR")
    score_base = 90 if severity == "ERROR" else 70
    if confidence == "medium":
        score_base -= 15
    if confidence == "low":
        score_base -= 30
    if len(vuln.get("engines", [])) > 1:
        score_base += 5
    # 处理 engines 字段：优先使用 engines，否则从 engine 构建
    engines = vuln.get("engines")
    if engines is None:
        engine = vuln.get("engine", "ast")
        engines = [engine]

    # 路径规范化：将绝对路径转为相对路径
    raw_file = vuln.get("file", "")
    if root and raw_file:
        file_display = _normalize_file_path(raw_file, root)
    else:
        file_display = str(raw_file).replace("\\", "/")

    finding_output: dict[str, Any] = {
        "type": vuln["type"],
        "severity": severity,
        "cwe": cwe,
        "confidence": confidence,
        "risk_score": max(0, min(score_base, 100)),
        "engines": engines,
        "file": file_display,
        "line": vuln.get("line", 0),
        "language": vuln.get("language", "Python"),
    }
    # 保留检测器原始 message
    if message:
        finding_output["message"] = message
    # 保留 metadata 字段（包含污点追踪信息）
    if "metadata" in vuln:
        finding_output["metadata"] = vuln["metadata"]
    finding_output["bilingual"] = _build_bilingual_finding(finding_output)
    return finding_output


def _analyze_repo(repo_root: Path) -> dict[str, Any]:
    """分析仓库中的代码文件，检测漏洞"""
    findings: list[dict[str, Any]] = []
    skipped_details: list[dict[str, str]] = []
    scanned_files: list[dict[str, Any]] = []
    # 使用 LanguageRouter 统一调度多语言检测
    router = LanguageRouter()
    for code_file in _collect_code_files(repo_root):
        file_record: dict[str, Any] = {
            "file": str(code_file.relative_to(repo_root)).replace("\\", "/"),
            "detected_language": None,
            "detector": None,
            "finding_count": 0,
            "status": "pending",
            "error": None,
        }
        try:
            # 检测语言
            detected_lang = router.detect_language(str(code_file))
            file_record["detected_language"] = detected_lang
            file_record["status"] = "scanning"

            # 扫描文件
            file_findings = router.scan_file(str(code_file))
            file_record["finding_count"] = len(file_findings)
            file_record["status"] = "completed"
            file_record["detector"] = "LanguageRouter"
            findings.extend(file_findings)
        except Exception as exc:
            file_record["status"] = "error"
            file_record["error"] = str(exc)
            skipped_details.append(
                _build_skipped_detail(code_file, repo_root, "检测引擎", exc)
            )
        scanned_files.append(file_record)

    findings = _dedup_findings(findings)
    out_findings = [_build_finding_output(v, root=repo_root) for v in findings]
    skipped_files = []
    for item in skipped_details:
        file_name = item["file"]
        if file_name not in skipped_files:
            skipped_files.append(file_name)
    return {
        "analysis_mode": "detect-only",
        "languages": list(SUPPORTED_LANGUAGES),
        "vulnerabilities": out_findings,
        "count": len(out_findings),
        "skipped_files": skipped_files,
        "skipped_details": skipped_details,
        "scanned_files": scanned_files,
        "display": _build_display(
            vulnerabilities=out_findings,
            skipped_details=skipped_details,
        ),
    }


def analyze_input(
    input_type: str,
    code: str | None = None,
    repo_url: str | None = None,
    progress_callback: Any | None = None,
    language_hint: str | None = None,
) -> dict[str, Any]:
    """执行漏洞检测分析

    Args:
        input_type: 输入类型，"code" 或 "github"
        code: 代码片段（input_type="code" 时使用）
        repo_url: GitHub 仓库 URL（input_type="github" 时使用）
        progress_callback: 进度回调函数 (stage, progress, message) -> None
        language_hint: 语言提示
    """
    def emit(stage: str, progress: int, message: str) -> None:
        if callable(progress_callback):
            progress_callback(stage, progress, message)

    with tempfile.TemporaryDirectory(prefix="security_input_") as tmp:
        tmp_root = Path(tmp)
        repo_root = tmp_root / "repo"
        repo_root.mkdir(parents=True, exist_ok=True)
        emit("prepare", 5, "初始化临时分析目录")

        code_snippet_diagnostic: dict[str, Any] | None = None

        if input_type == "code":
            if not code or not code.strip():
                raise ValueError("代码输入不能为空。")
            file_path, detected_lang, diagnostic = _write_code_snippet(
                repo_root, code, language_hint
            )
            code_snippet_diagnostic = diagnostic
            emit("prepare", 15, f"已写入代码片段 ({detected_lang}: {file_path.name})")
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
        analysis = _analyze_repo(repo_root)
        emit("report", 85, "漏洞检测完成，正在整理分析报告")
        analysis["input_type"] = input_type
        if input_type == "github":
            analysis["repo_url"] = repo_url
        # 添加代码片段诊断信息
        if code_snippet_diagnostic:
            analysis["code_snippet_info"] = code_snippet_diagnostic
        emit("done", 100, "分析完成")
        return analysis
