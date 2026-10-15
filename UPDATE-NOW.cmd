@echo off
title Update Windows safely
echo.
echo  Unblocks Windows Update, installs updates, then puts the block back
echo  automatically - including across the reboot.
echo  A UAC prompt will appear - click Yes.
echo.
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0Invoke-UpdateWindow.ps1"
