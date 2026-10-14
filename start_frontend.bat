@echo off
title BrandShield AI - Astro Frontend (Port 4321)
cd /d "%~dp0frontend"
echo ===================================================
echo   Starting BrandShield AI Astro Frontend
echo   URL: http://127.0.0.1:4321
echo ===================================================
echo.
call npx astro dev --host 127.0.0.1 --port 4321
if %ERRORLEVEL% NEQ 0 (
    echo.
    echo [ERROR] Frontend exited with error code %ERRORLEVEL%.
)
echo.
pause
