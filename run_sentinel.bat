@echo off
title Technocore Sentinel Control Hub
color 0b
echo ===================================================================
echo     TECHNOCORE SENTINEL - Security Engine ^& Agent Control Hub
echo ===================================================================
echo.
echo [*] Starting Sentinel Web Server on http://127.0.0.1:5050 ...
start http://127.0.0.1:5050
python dashboard.py 5050
pause
