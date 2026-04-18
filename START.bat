@echo off
title AI-NGFW Security Command Center
color 0A

cd /d "%~dp0"

echo.
echo  =====================================================
echo   AI-NGFW SECURITY COMMAND CENTER
echo  =====================================================
echo.
echo  [1/2] Installing dependencies (if needed)...
call npm install --silent 2>nul

echo  [2/2] Starting servers in background...
start "App Server" node app/appServer.js
timeout /t 2 /nobreak >nul
start "Firewall Server" node backend/firewallServer.js

echo.
echo  =====================================================
echo.
echo   COPY YOUR URLs BELOW:
echo.
echo   Dashboard  ^>^>  http://localhost:4000/dashboard
echo   Firewall   ^>^>  http://localhost:4000
echo.
echo  =====================================================
echo.
echo  Both servers are running in separate windows.
echo  Close those windows to stop the servers.
echo.
pause
