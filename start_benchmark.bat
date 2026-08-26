@echo off
title NRA Network - DNS Optimizer
color 0F

setlocal EnableExtensions
:: ?? Silent UAC Auto-Elevation ??????????????????????????????????????
>nul 2>&1 "%SYSTEMROOT%\system32\cacls.exe" "%SYSTEMROOT%\system32\config\system"
if '%errorlevel%' NEQ '0' (
    echo Requesting Administrative privileges for DNS and Network tuning...
    goto UACPrompt
) else ( goto gotAdmin )

:UACPrompt
    echo Set UAC = CreateObject^("Shell.Application"^) > "%temp%\getadmin.vbs"
    set CMD_LINE_ARGS=
    :Win9xArg
    if ""%1""=="""" goto Win9xArgDone
    set CMD_LINE_ARGS=%CMD_LINE_ARGS% %1
    shift
    goto Win9xArg
    :Win9xArgDone
    echo UAC.ShellExecute "cmd.exe", "/c ""%~s0"" %CMD_LINE_ARGS%", "", "runas", 1 >> "%temp%\getadmin.vbs"
    "%temp%\getadmin.vbs"
    del "%temp%\getadmin.vbs"
    exit /B

:gotAdmin
    pushd "%CD%"
    CD /D "%~dp0"

set "DO_PAUSE=1"
echo %* | findstr /I "BenchmarkOnly Fastest Gaming Reset" >nul
if %errorlevel% EQU 0 set DO_PAUSE=0

:: ?? Detect PowerShell 7+ (pwsh) first, fallback to 5.1 ?????????????
where pwsh >nul 2>&1
if %errorlevel% EQU 0 (
    echo [*] Using PowerShell 7+ ^(pwsh^)
    pwsh -NoProfile -ExecutionPolicy Bypass -File "%~dp0dns_benchmark.ps1" %*
) else (
    echo [*] Using PowerShell 5.1
    powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0dns_benchmark.ps1" %*
)
if "%DO_PAUSE%"=="1" pause

