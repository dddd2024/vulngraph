@echo off
setlocal
cd /d "%~dp0"

if not exist ".venv\Scripts\python.exe" (
  echo [setup] creating virtual environment...
  python -m venv .venv
  .\.venv\Scripts\python -m pip install --upgrade pip
  .\.venv\Scripts\python -m pip install -r requirements.txt
)

start "" http://127.0.0.1:8000
.\.venv\Scripts\python -m uvicorn api.server:app --host 127.0.0.1 --port 8000 --reload

