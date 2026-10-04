@echo off
rem Installs AWS Kit for your Windows user. No admin rights needed.
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0windows\install.ps1" %*
echo.
pause
