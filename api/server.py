import json
import os
import threading
import time
import uuid
from pathlib import Path
from typing import Any

from analysis_engine import analyze_input
from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from demo_tools import reset_demo_state, run_demo_tests
from graph.vuln_knowledge_graph import (
    build_vulnerability_knowledge_graph,
    sync_knowledge_graph_to_neo4j,
)
from main import run_pipeline
from parser.call_graph import build_call_graph, export_edges

app = FastAPI(title="AI Vulnerability Auto-Fix Demo")
ROOT = Path(__file__).resolve().parents[1]
app.mount("/ui", StaticFiles(directory=str(ROOT / "ui")), name="ui")
JOBS: dict[str, dict[str, Any]] = {}
JOBS_LOCK = threading.Lock()


class AnalyzeInputRequest(BaseModel):
    input_type: str = Field(pattern="^(code|github)$")
    ai_mode: str = Field(default="rule", pattern="^(rule|cloud|local)$")
    model_name: str | None = None
    code: str | None = None
    repo_url: str | None = None


class KnowledgeGraphRequest(BaseModel):
    vulnerabilities: list[dict[str, Any]]
    ai_mode: str = Field(default="rule", pattern="^(rule|cloud|local)$")
    model_name: str | None = None
    sync_neo4j: bool = True


def _strip_env_value(raw: str) -> str:
    value = raw.strip()
    if not value:
        return ""
    if value[0] == value[-1] and value[0] in {"'", '"'}:
        return value[1:-1].strip()
    if "#" in value:
        value = value.split("#", 1)[0].strip()
    return value


def _read_env_file_values() -> dict[str, str]:
    env_path = ROOT / ".env"
    if not env_path.exists():
        return {}
    parsed: dict[str, str] = {}
    for raw_line in env_path.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, raw_value = line.split("=", 1)
        key = key.strip().removeprefix("export ").strip()
        if not key:
            continue
        parsed[key] = _strip_env_value(raw_value)
    return parsed


def _split_model_list(raw: str | None) -> list[str]:
    if not raw:
        return []
    items = [p.strip() for p in raw.replace(";", ",").split(",")]
    return [p for p in items if p]


def _dedup_keep_order(items: list[str]) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for item in items:
        if item in seen:
            continue
        seen.add(item)
        out.append(item)
    return out


def _get_model_catalog() -> dict[str, Any]:
    env_file = _read_env_file_values()

    def env_value(key: str) -> str | None:
        return env_file.get(key) or os.getenv(key)

    cloud_single_keys = ["OPENAI_MODEL", "DOUBAO_MODEL", "ARK_MODEL"]
    cloud_list_keys = ["OPENAI_MODELS", "DOUBAO_MODELS", "ARK_MODELS", "CLOUD_MODELS"]
    local_single_keys = ["LOCAL_LLM_MODEL", "OLLAMA_MODEL"]
    local_list_keys = ["LOCAL_LLM_MODELS", "OLLAMA_MODELS"]

    cloud_models = [env_value(k) or "" for k in cloud_single_keys]
    for key in cloud_list_keys:
        cloud_models.extend(_split_model_list(env_value(key)))
    cloud_models = _dedup_keep_order([m for m in cloud_models if m])

    local_models = [env_value(k) or "" for k in local_single_keys]
    for key in local_list_keys:
        local_models.extend(_split_model_list(env_value(key)))
    local_models = _dedup_keep_order([m for m in local_models if m])

    return {
        "cloud": {
            "default_model": env_value("OPENAI_MODEL")
            or env_value("DOUBAO_MODEL")
            or env_value("ARK_MODEL"),
            "models": cloud_models,
        },
        "local": {
            "default_model": env_value("LOCAL_LLM_MODEL") or env_value("OLLAMA_MODEL"),
            "models": local_models,
        },
    }


def _update_job(job_id: str, **kwargs: Any) -> None:
    with JOBS_LOCK:
        if job_id in JOBS:
            JOBS[job_id].update(kwargs)
            JOBS[job_id]["updated_at"] = time.time()


@app.get("/")
def index() -> FileResponse:
    return FileResponse(str(ROOT / "ui" / "index.html"))


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/config/models")
def config_models() -> dict[str, Any]:
    return _get_model_catalog()


@app.post("/analyze")
def analyze() -> dict[str, Any]:
    try:
        return run_pipeline(str(ROOT))
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@app.post("/analyze-input")
def analyze_input_api(payload: AnalyzeInputRequest) -> dict[str, Any]:
    try:
        return analyze_input(
            input_type=payload.input_type,
            ai_mode=payload.ai_mode,
            model_name=payload.model_name,
            code=payload.code,
            repo_url=payload.repo_url,
        )
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.post("/analyze-input-async")
def analyze_input_async(payload: AnalyzeInputRequest) -> dict[str, Any]:
    job_id = uuid.uuid4().hex
    with JOBS_LOCK:
        JOBS[job_id] = {
            "job_id": job_id,
            "status": "queued",
            "stage": "queued",
            "progress": 0,
            "message": "任务已创建",
            "result": None,
            "error": None,
            "created_at": time.time(),
            "updated_at": time.time(),
        }

    def runner() -> None:
        _update_job(job_id, status="running", stage="start", progress=1, message="任务启动")

        def on_progress(stage: str, progress: int, message: str) -> None:
            _update_job(
                job_id,
                status="running",
                stage=stage,
                progress=progress,
                message=message,
            )

        try:
            result = analyze_input(
                input_type=payload.input_type,
                ai_mode=payload.ai_mode,
                model_name=payload.model_name,
                code=payload.code,
                repo_url=payload.repo_url,
                progress_callback=on_progress,
            )
            _update_job(
                job_id,
                status="completed",
                stage="done",
                progress=100,
                message="完成",
                result=result,
            )
        except Exception as exc:
            _update_job(
                job_id,
                status="failed",
                stage="error",
                progress=100,
                message="失败",
                error=str(exc),
            )

    threading.Thread(target=runner, daemon=True).start()
    return {"job_id": job_id, "status": "queued"}


@app.get("/jobs/{job_id}")
def get_job(job_id: str) -> dict[str, Any]:
    with JOBS_LOCK:
        job = JOBS.get(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="job not found")
    return job


@app.post("/reset")
def reset() -> dict[str, Any]:
    try:
        return reset_demo_state(str(ROOT))
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@app.post("/run-tests")
def run_tests() -> dict[str, Any]:
    try:
        auto_generated = False
        if not (ROOT / "tests" / "test_fix.py").exists():
            run_pipeline(str(ROOT))
            auto_generated = True
        result = run_demo_tests(str(ROOT))
        result["auto_generated"] = auto_generated
        if auto_generated:
            result["message"] = "未检测到 test_fix.py，已自动先执行分析与补丁生成。"
        return result
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@app.get("/graph")
def graph() -> dict[str, Any]:
    g = build_call_graph(str(ROOT / "repo"))
    return {"edges": export_edges(g)}


@app.post("/knowledge-graph")
def knowledge_graph(payload: KnowledgeGraphRequest) -> dict[str, Any]:
    if not payload.vulnerabilities:
        raise HTTPException(status_code=400, detail="vulnerabilities 不能为空。")
    graph_data = build_vulnerability_knowledge_graph(
        payload.vulnerabilities, ai_mode=payload.ai_mode, model_name=payload.model_name
    )
    output: dict[str, Any] = {
        "graph": graph_data,
        "ai_mode": payload.ai_mode,
        "model_name": payload.model_name,
    }
    if payload.sync_neo4j:
        output["neo4j"] = sync_knowledge_graph_to_neo4j(graph_data)
    return output


@app.get("/result")
def result() -> dict[str, Any]:
    path = ROOT / "pipeline_result.json"
    if not path.exists():
        return {"status": "empty"}
    return json.loads(path.read_text(encoding="utf-8"))


@app.get("/artifact/fix.patch")
def artifact_patch() -> FileResponse:
    path = ROOT / "fix.patch"
    if not path.exists():
        raise HTTPException(status_code=404, detail="fix.patch not found")
    return FileResponse(str(path))


