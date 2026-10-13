@echo off
title BrandShield AI - FastAPI Backend Server (Port 8000)
cd /d "%~dp0"
echo Starting BrandShield AI Multi-Modal Detection Engine on http://localhost:8000 ...
if exist ".venv\Scripts\python.exe" (
    ".venv\Scripts\python.exe" -m uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload --reload-dir "%~dp0app"
) else (
    python -m uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload --reload-dir "%~dp0app"
)
pause
