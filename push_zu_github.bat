@echo off
title Curavio -> GitHub Upload
color 0A
cd /d "%~dp0"

REM Node Pfad
if exist "C:\node.exe" set "PATH=%PATH%;C:\"
if exist "C:\Program Files\nodejs\node.exe" set "PATH=%PATH%;C:\Program Files\nodejs"

echo ============================================
echo  Curavio wird zu GitHub hochgeladen...
echo ============================================
echo.

REM Git suchen
set "GITPATH="
if exist "C:\Program Files\Git\cmd\git.exe" set "GITPATH=C:\Program Files\Git\cmd"
if exist "C:\Program Files (x86)\Git\cmd\git.exe" set "GITPATH=C:\Program Files (x86)\Git\cmd"

if not "%GITPATH%"=="" set "PATH=%PATH%;%GITPATH%"

git --version >nul 2>&1
if errorlevel 1 (
    echo Git ist nicht installiert.
    echo.
    echo Bitte Git herunterladen und installieren:
    echo   https://git-scm.com/download/win
    echo.
    echo Danach dieses Skript nochmal ausfuehren.
    pause
    exit /b 1
)

echo Git gefunden!
echo.

REM .gitignore sicherstellen
if not exist ".gitignore" (
    echo node_modules/ > .gitignore
    echo .env >> .gitignore
    echo *.db >> .gitignore
    echo *.log >> .gitignore
)

REM Git initialisieren falls noetig
if not exist ".git\" (
    echo Initialisiere Git...
    git init
    git branch -M main
)

REM Remote setzen
git remote remove origin >nul 2>&1
git remote add origin https://github.com/nicklasspelten-netizen/Curavio.git

REM Git Identitaet setzen
git config --global user.email "nicklas.spelten@therapiezentrum.com"
git config --global user.name "Nicklas Spelten"

REM Git Lock-Dateien entfernen (falls vorhanden)
if exist ".git\index.lock" (
    echo Lock-Datei gefunden, wird entfernt...
    del /f ".git\index.lock"
)
if exist ".git\HEAD.lock" (
    del /f ".git\HEAD.lock"
)

REM Alles hinzufuegen und committen
echo Dateien werden vorbereitet...
git add -A
git commit -m "Curavio Update"

echo.
echo Lade hoch zu GitHub...
echo (Browser-Fenster zur Anmeldung kann sich oeffnen)
echo.
git push -u origin main

if errorlevel 1 (
    echo.
    echo Fehler beim Upload. Versuche mit --force...
    git push -u origin mai