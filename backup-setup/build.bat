@echo off
setlocal enabledelayedexpansion

echo ============================================
echo   ServerManager Backup Setup - Build EXE
echo ============================================
echo.

cd /d "%~dp0"

where python >nul 2>&1
if errorlevel 1 (
    echo ERROR: Python not found. Install Python 3.11+ from https://python.org
    exit /b 1
)

echo Creating virtual environment...
python -m venv .venv
call .venv\Scripts\activate.bat

echo Installing dependencies...
pip install -r requirements.txt

echo Building executable...
pyinstaller --clean ServerManager-Backup-Setup.spec

if exist "dist\ServerManager-Backup-Setup.exe" (
    echo.
    echo ============================================
    echo   Build successful!
    echo   Output: dist\ServerManager-Backup-Setup.exe
    echo ============================================
) else (
    echo Build failed.
    exit /b 1
)

endlocal
