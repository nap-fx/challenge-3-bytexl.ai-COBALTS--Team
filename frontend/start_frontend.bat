@echo off
title BrandShield AI - Astro Frontend (Port 4321)
cd /d "%~dp0"
echo Starting BrandShield AI Frontend on http://localhost:4321 ...
npx astro dev --host 0.0.0.0 --port 4321
pause
