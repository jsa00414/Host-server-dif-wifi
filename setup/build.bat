@echo off
setlocal enabledelayedexpansion

echo ============================================
echo   VPS WireGuard Setup - Build Windows EXE
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
pyinstaller --clean VPS-WireGuard-Setup.spec

if exist "dist\VPS-WireGuard-Setup.exe" (
    echo.
    echo ============================================
    echo   Build successful!
    echo   Output: dist\VPS-WireGuard-Setup.exe
    echo ============================================
) else (
    echo Build failed.
    exit /b 1
)

endlocal
