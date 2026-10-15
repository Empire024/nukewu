@echo off
title Nuke Windows Update
echo.
echo  This disables Windows Update and LOCKS it so Windows cannot undo it.
echo  You will receive no security patches until you run UNDO-WINDOWS-UPDATE.cmd
echo  A UAC prompt will appear - click Yes.
echo.
pause
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0Disable-WindowsUpdate.ps1"
echo.
pause
