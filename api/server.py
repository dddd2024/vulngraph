"""
VulnPatch API Server.

This module is responsible ONLY for:
  1. Creating the FastAPI app
  2. Mounting the UI static files
  3. Registering route modules via include_router
  4. A minimal set of root-level routes (/, /health, /config/models)

All business logic lives in api/routes/ submodules.
"""

import os
from pathlib import Path
from typing import Any

from fastapi import FastAPI
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from api.routes import agents, evidence, findings, findings_filter, report, scan, scans, sessions, stats

app = FastAPI(title="VulnPatch - Security Audit Platform")

ROOT = Path(__file__).resolve().parents[1]

# ---------------------------------------------------------------------------
# Static files
# ---------------------------------------------------------------------------
app.mount("/ui", StaticFiles(directory=str(ROOT / "ui")), name="ui")

# ---------------------------------------------------------------------------
# Register route modules
# ---------------------------------------------------------------------------
app.include_router(scan.router)       # POST /scan
app.include_router(findings.router)   # GET  /findings
app.include_router(evidence.router)   # GET  /evidence
app.include_router(agents.router)     # GET  /agents/logs
app.include_router(report.router)     # GET  /report/json, /report/markdown, /report/html
app.include_router(scans.router)      # GET /scans/{scan_id}/findings, /scans/{scan_id}/evidence, etc.
app.include_router(sessions.router)   # GET  /scans (list), DELETE /scans/{scan_id}
app.include_router(stats.router)      # GET  /stats
app.include_router(findings_filter.router)  # GET  /findings/filter

# ---------------------------------------------------------------------------
# Root-level routes (minimal)
# ---------------------------------------------------------------------------


@app.get("/")
def index() -> FileResponse:
    return FileResponse(str(ROOT / "ui" / "index.html"))


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/config/models")
def config_models() -> dict[str, Any]:
    """Return available model list (for knowledge-graph AI config)."""
    return _get_model_catalog()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

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
    return [p.strip() for p in raw.replace(";", ",").split(",") if p.strip()]


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
