@echo off
setlocal
"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -ExecutionPolicy Bypass -File "%~dp0Collect-SteamObserve.ps1" %*
set "RS2CollectExit=%ERRORLEVEL%"
pause
exit /b %RS2CollectExit%
