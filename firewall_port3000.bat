@echo off
echo Oeffne Port 3000 fuer Curavio...
netsh advfirewall firewall add rule name="Curavio Port 3000" dir=in action=allow protocol=TCP localport=3000
echo.
echo Fertig! Port 3000 ist jetzt offen.
echo Handy kann die App nun erreichen.
pause
