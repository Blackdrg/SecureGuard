@echo off
REM ============================================================================
REM SecureGuard Kernel Driver Build Script
REM 
REM This script builds the SecureGuard kernel driver.
REM Requirements:
REM   - Windows Driver Kit (WDK) installed
REM   - Visual Studio with C++ support
REM   - Windows SDK (matching WDK version)
REM ============================================================================

echo ========================================
echo SecureGuard Kernel Driver Builder
echo ========================================
echo.

REM Check for WDK
if not exist "%WDK_DIR%" (
    echo ERROR: Windows Driver Kit not found!
    echo Please install WDK and set WDK_DIR environment variable.
    echo Example: set WDK_DIR=C:\Program Files (x86)\Windows Kits\10
    exit /b 1
)

REM Set paths
set DRIVER_DIR=%~dp0
set SOURCE_DIR=%DRIVER_DIR%
set OBJ_DIR=%DRIVER_DIR%obj
set BIN_DIR=%DRIVER_DIR%bin

echo Driver Source: %SOURCE_DIR%
echo.

REM Create output directories
if not exist "%OBJ_DIR%" mkdir "%OBJ_DIR%"
if not exist "%BIN_DIR%" mkdir "%BIN_DIR%"

REM Build command (using MSBuild from WDK)
echo Building SecureGuardDriver.sys...
echo.

REM Check for signtool
set SIGNTOOL=
if exist "%WDK_DIR%\bin\x64\signtool.exe" (
    set SIGNTOOL=%WDK_DIR%\bin\x64\signtool.exe
) else if exist "%WDK_DIR%\bin\x86\signtool.exe" (
    set SIGNTOOL=%WDK_DIR%\bin\x86\signtool.exe
)

REM Note: Actual build requires WDK/MSBuild
REM For now, this is a placeholder for the build process

echo.
echo ========================================
echo Driver build configuration:
echo ========================================
echo.
echo Source Files:
echo   - SecureGuardDriver.c
echo   - SecureGuardComm.cpp
echo.
echo Output:
echo   - SecureGuardDriver.sys (Kernel Driver)
echo   - SecureGuardComm.dll (User-mode DLL)
echo.
echo To build the driver:
echo   1. Open Visual Studio Developer Command Prompt
echo   2. Navigate to this directory
echo   3. Run: msbuild SecureGuardDriver.sln /p:Configuration=Release
echo.
echo IMPORTANT: The driver MUST be code-signed for production use!
echo   - For testing: Enable Test Signing (bcdedit /set testsigning on)
echo   - For production: Sign with EV Certificate or Microsoft WHQL
echo.

pause

