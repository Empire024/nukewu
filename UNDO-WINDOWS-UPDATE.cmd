@echo off
title Restore Windows Update
echo.
echo  This puts Windows Update back to normal and removes the block.
echo  A UAC prompt will appear - click Yes.
echo.
pause
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0Enable-WindowsUpdate.ps1"
echo.
pause
