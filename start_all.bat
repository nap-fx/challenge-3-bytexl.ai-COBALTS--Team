@echo off
title BrandShield AI - Master Launcher
cd /d "%~dp0"
echo ===================================================
echo   BrandShield AI - Autonomous Impersonation Defense
echo   Launching Backend (Port 8000) and Frontend (Port 4321)
echo ===================================================
echo.

echo Starting FastAPI Backend window...
start "BrandShield Backend" cmd /c "%~dp0start_backend.bat"

echo Waiting for backend initialization...
ping -n 3 127.0.0.1 >nul

echo Starting Astro Frontend window...
start "BrandShield Frontend" cmd /c "%~dp0start_frontend.bat"

echo.
echo ===================================================
echo   Both services dispatched!
echo   Frontend : http://127.0.0.1:4321
echo   Backend  : http://127.0.0.1:8000
echo   API Docs : http://127.0.0.1:8000/docs
echo ===================================================
echo Keep this window or the spawned windows open.
echo.
pause
