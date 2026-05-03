@echo off
title LibreHealth EHR Security Dashboard - PHP
cd /d "%~dp0"

where php >nul 2>&1
if errorlevel 1 (
  echo PHP is not in PATH. Install PHP or add it to PATH, then run:
  echo   php -S localhost:8000 router.php
  pause
  exit /b 1
)

echo Starting server at http://localhost:8000/
echo Open that URL in your browser. Press Ctrl+C to stop.
echo.
start "" "http://localhost:8000/"
php -S localhost:8000 router.php
pause
