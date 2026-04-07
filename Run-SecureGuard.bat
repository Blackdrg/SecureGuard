@echo off
echo Starting SecureGuard Enterprise Antivirus...
echo.
cd /d "%~dp0publish"
start SecureGuard.exe
echo.
echo The application is starting...
echo Web dashboard will be available at http://localhost:8765
echo.
echo If nothing appears, try running as Administrator.
pause

