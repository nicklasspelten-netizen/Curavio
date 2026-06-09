@echo off
title Git installieren
echo Installiere Git automatisch...
echo (dauert ca. 1-2 Minuten)
echo.
winget install --id Git.Git -e --source winget
echo.
echo Git ist installiert! Fenster kann geschlossen werden.
pause
