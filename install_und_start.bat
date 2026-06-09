@echo off
title Curavio
color 0A
cd /d "%~dp0"

REM Node.js Pfad ermitteln
if exist "C:\node.exe"                          set "PATH=%PATH%;C:\"
if exist "C:\Program Files\nodejs\node.exe"     set "PATH=%PATH%;C:\Program Files\nodejs"

REM Node pruefen
node --version >nul 2>&1
if errorlevel 1 (
    echo FEHLER: node.exe nicht gefunden!
    echo Bitte Node.js von https://nodejs.org installieren.
    pause
    exit /b 1
)

echo Node.js gefunden:
node --version

REM Alte node_modules komplett entfernen fuer saubere Installation
echo Bereinige alte Module...
if exist "node_modules\" rmdir /s /q node_modules

REM Pakete installieren
echo Installiere Pakete - bitte warten...
call npm install --no-audit --no-fund
if errorlevel 1 (
    echo.
    echo FEHLER bei npm install - versuche mit --legacy-peer-deps...
    call npm install --legacy-peer-deps --no-audit --no-fund
    if errorlevel 1 (
        echo FEHLER: Installation fehlgeschlagen.
        pause
        exit /b 1
    )
)

echo.
echo  =========================================
echo   CURAVIO laeuft unter: http://localhost:3000
echo  =========================================
echo.
echo  Login:
echo    Angehoeriger : thomas@demo.de / curavio123
echo    Betreuer     : maria@demo.de / curavio123
echo    Admin        : admin@curavio.de / curavio123
echo.

node server.js
pause
