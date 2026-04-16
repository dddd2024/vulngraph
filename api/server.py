import json
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
    code: str | None = None
    repo_url: str | None = None


class KnowledgeGraphRequest(BaseModel):
    vulnerabilities: list[dict[str, Any]]
    ai_mode: str = Field(default="rule", pattern="^(rule|cloud|local)$")
    sync_neo4j: bool = True


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
        payload.vulnerabilities, ai_mode=payload.ai_mode
    )
    output: dict[str, Any] = {
        "graph": graph_data,
        "ai_mode": payload.ai_mode,
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


