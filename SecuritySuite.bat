@echo off
:: SecuritySuite - Launcher con elevacion UAC
:: Si no tiene admin, relanza como administrador
net session >nul 2>&1
if %errorlevel% neq 0 (
    powershell -Command "Start-Process cmd -ArgumentList '/c cd /d ""%~dp0"" && powershell -ExecutionPolicy Bypass -WindowStyle Hidden -File SecuritySuite.ps1' -Verb RunAs"
    exit /b
)
cd /d "%~dp0"
powershell -ExecutionPolicy Bypass -WindowStyle Hidden -File SecuritySuite.ps1
