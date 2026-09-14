@echo off
setlocal
set "_rs2_ps=%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe"
if exist "%SystemRoot%\Sysnative\WindowsPowerShell\v1.0\powershell.exe" set "_rs2_ps=%SystemRoot%\Sysnative\WindowsPowerShell\v1.0\powershell.exe"
"%_rs2_ps%" -NoLogo -NoProfile -File "%~dp0Run-M1RChecks.ps1" -Stage Active %*
set "_rs2_exit=%errorlevel%"
if "%~1"=="" pause
endlocal & exit /b %_rs2_exit%
