@echo off

title Network Catalog

echo ============================================================
echo Starting Network Catalog
echo ============================================================

echo.
echo [1/2] Running active scanner...
echo.

py scanner.py

echo.
echo ============================================================
echo Scanner complete
echo ============================================================

echo.
echo [2/2] Starting passive traffic monitor...
echo Press CTRL+C to stop monitoring.
echo.

py traffic.py

pause