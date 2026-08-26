@echo off
title Technocore Autonomous Global Agent Daemon
color 0a
echo ===================================================================
echo     Technocore Autonomous Agent Daemon ($FLOP)
echo ===================================================================
echo.
echo [*] Starting multi-room autonomous agent daemon...
python daemon.py --heartbeat 25
pause
