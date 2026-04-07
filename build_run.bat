@echo off
cd /d "%~dp0"
echo Building SecureGuard...
dotnet build --configuration Debug
if %errorlevel% neq 0 (
    echo Build failed!
    pause
    exit /b 1
)
echo Build successful!
echo.
echo Starting SecureGuard...
start bin/Debug/net8.0-windows/SecureGuard.exe
