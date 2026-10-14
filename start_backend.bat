@echo off
title BrandShield AI - FastAPI Backend (Port 8000)
cd /d "%~dp0backend"
echo ===================================================
echo   Starting BrandShield AI FastAPI Backend
echo   URL: http://127.0.0.1:8000
echo   Docs: http://127.0.0.1:8000/docs
echo ===================================================
echo.

set "PY_EXE=%~dp0backend\.venv\Scripts\python.exe"
if exist "%PY_EXE%" (
    echo Using Virtual Environment Python
    "%PY_EXE%" -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
) else (
    echo Using System Python
    python -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
)

echo.
echo [INFO] Backend process ended.
pause
