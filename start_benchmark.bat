@echo off
title NRA Network - DNS Optimizer
color 0F

:: ── Silent UAC Auto-Elevation ──────────────────────────────────────
>nul 2>&1 "%SYSTEMROOT%\system32\cacls.exe" "%SYSTEMROOT%\system32\config\system"
if '%errorlevel%' NEQ '0' (
    echo Requesting Administrative privileges for DNS and Network tuning...
    goto UACPrompt
) else ( goto gotAdmin )

:UACPrompt
    echo Set UAC = CreateObject^("Shell.Application"^) > "%temp%\getadmin.vbs"
    echo UAC.ShellExecute "cmd.exe", "/c ""%~s0""", "", "runas", 1 >> "%temp%\getadmin.vbs"
    "%temp%\getadmin.vbs"
    del "%temp%\getadmin.vbs"
    exit /B

:gotAdmin
    pushd "%CD%"
    CD /D "%~dp0"

:: ── Detect PowerShell 7+ (pwsh) first, fallback to 5.1 ─────────────
where pwsh >nul 2>&1
if %errorlevel% EQU 0 (
    echo [*] Using PowerShell 7+ ^(pwsh^)
    pwsh -NoProfile -ExecutionPolicy Bypass -File "%~dp0dns_benchmark.ps1"
) else (
    echo [*] Using PowerShell 5.1
    powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0dns_benchmark.ps1"
)
pause
