@echo off
title Check for critical updates
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0Check-CriticalUpdates.ps1"
echo.
pause
