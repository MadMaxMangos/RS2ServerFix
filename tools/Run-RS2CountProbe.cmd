@echo off
setlocal
set "RS2CountPS=%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe"
if exist "%SystemRoot%\Sysnative\WindowsPowerShell\v1.0\powershell.exe" set "RS2CountPS=%SystemRoot%\Sysnative\WindowsPowerShell\v1.0\powershell.exe"
"%RS2CountPS%" -NoProfile -ExecutionPolicy Bypass -File "%~dp0Collect-RS2CountProbe.ps1" %*
set "RS2CountExit=%ERRORLEVEL%"
pause
exit /b %RS2CountExit%
