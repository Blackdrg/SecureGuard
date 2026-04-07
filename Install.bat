@echo off
setlocal enabledelayedexpansion

:: SecureGuard Antivirus Installer
:: ================================

title SecureGuard Antivirus Installer
color 0a

echo.
echo ================================================
echo    SecureGuard Antivirus Installer v2024.1
echo ================================================
echo.

:: Check for Python
python --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Python is not installed or not in PATH
    echo Please install Python 3.8 or higher from https://python.org
    pause
    exit /b 1
)

:: Get installation directory
set "INSTALL_DIR=C:\Program Files\SecureGuard"
echo Installing to: %INSTALL_DIR%
echo.

:: Create installation directory
echo [*] Creating installation directory...
mkdir "%INSTALL_DIR%" 2>nul
if errorlevel 1 (
    echo [ERROR] Cannot create installation directory
    echo Please run as Administrator
    pause
    exit /b 1
)

:: Copy files
echo [*] Copying application files...
xcopy /E /Y /Q "%~dp0deployment\*" "%INSTALL_DIR%\" >nul
if errorlevel 1 (
    echo [ERROR] Failed to copy files
    pause
    exit /b 1
)

:: Create Start Menu shortcuts
echo [*] Creating Start Menu shortcuts...
mkdir "%ProgramData%\Microsoft\Windows\Start Menu\Programs\SecureGuard" 2>nul
echo @echo off > "%ProgramData%\Microsoft\Windows\Start Menu\Programs\SecureGuard\SecureGuard.bat"
echo python "%INSTALL_DIR%\main.py" >> "%ProgramData%\Microsoft\Windows\Start Menu\Programs\SecureGuard\SecureGuard.bat"

:: Create Desktop shortcut
echo [*] Creating Desktop shortcut...
powershell -Command "$ws = New-Object -ComObject WScript.Shell; $s = $ws.CreateShortcut('%USERPROFILE%\Desktop\SecureGuard.lnk'); $s.TargetPath = '%INSTALL_DIR%\SecureGuard.bat'; $s.WorkingDirectory = '%INSTALL_DIR%'; $s.Description = 'SecureGuard Antivirus'; $s.Save()"

:: Add to startup
echo [*] Configuring startup...
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "SecureGuard" /t REG_SZ /d "\"%INSTALL_DIR%\SecureGuard.bat\"" /f >nul 2>&1

:: Create uninstaller
echo [*] Creating uninstaller...
(
echo @echo off
echo echo Uninstalling SecureGuard Antivirus...
echo taskkill /f /im python.exe 2^>nul
echo rd /s /q "%INSTALL_DIR%"
echo rd /s /q "%ProgramData%\Microsoft\Windows\Start Menu\Programs\SecureGuard" 2^>nul
echo del "%USERPROFILE%\Desktop\SecureGuard.lnk" 2^>nul
echo reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "SecureGuard" /f 2^>nul
echo echo Uninstallation complete.
echo pause
) > "%INSTALL_DIR%\Uninstall.bat"

echo.
echo ================================================
echo    Installation Complete!
echo ================================================
echo.
echo SecureGuard Antivirus has been installed successfully!
echo.
echo To run: Search for "SecureGuard" in Start Menu
echo          or double-click Desktop shortcut
echo.
echo Note: Python must be installed on your system
echo.
pause
