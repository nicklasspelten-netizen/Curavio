@echo off
title Curavio App
color 0A
cls

echo.
echo  =========================================
echo   CURAVIO - App wird gestartet ...
echo  =========================================
echo.

:: Pruefen ob node_modules existiert
if not exist "node_modules\" (
    echo  [1/2] Pakete werden installiert (einmalig) ...
    echo.
    call npm install
    if errorlevel 1 (
        echo.
        echo  FEHLER: npm install fehlgeschlagen.
        echo  Bitte sicherstellen dass Node.js installiert ist.
        echo  Download: https://nodejs.org
        pause
        exit /b 1
    )
    echo.
    echo  Pakete erfolgreich installiert!
    echo.
)

echo  [2/2] Server wird gestartet ...
echo.
echo  =========================================
echo   App laeuft unter: http://localhost:3000
echo  =========================================
echo.
echo  Login:
echo    Angehoeriger : thomas@demo.de   / curavio123
echo    Betreuer     : maria@demo.de    / curavio123
echo    Admin        : admin@curavio.de / curavio123
echo.
echo  Zum Beenden: Fenster schliessen
echo.

node server.js

pause
