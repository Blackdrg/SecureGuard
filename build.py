"""
SecureGuard Antivirus - Build & Package Script
=============================================

This script builds the antivirus application into a distributable package.
Supports creating installer using various methods.
"""


import os
import sys
import shutil
import subprocess
from pathlib import Path
from datetime import datetime

# Configuration
APP_NAME = "SecureGuard Antivirus"
APP_VERSION = "1.0.0"
APP_PUBLISHER = "SecureGuard"
APP_URL = "https://secureguard.example.com"
INSTALL_DIR = "C:\\Program Files\\SecureGuard"
OUTPUT_DIR = "dist"


class BuildManager:
    def __init__(self):
        self.project_root = Path(__file__).parent
        self.dist_dir = self.project_root / OUTPUT_DIR
        self.build_dir = self.project_root / "build"

    def clean(self):
        """Clean previous builds"""
        print("[*] Cleaning previous builds...")

        # Remove dist directory
        if self.dist_dir.exists():
            shutil.rmtree(self.dist_dir)

        # Remove build directory
        if self.build_dir.exists():
            shutil.rmtree(self.build_dir)

        # Create fresh directories
        self.dist_dir.mkdir(exist_ok=True)

        print("[+] Clean complete")

    def copy_files(self):
        """Copy all required files"""
        print("[*] Copying application files...")

        # Copy main application files
        files_to_copy = [
            "main.py",
            "demo.py",
            "advanced_demo.py",
            "ui_demo.py",
            "quick_demo.py",
        ]

        dirs_to_copy = [
            "engine",
            "ai",
            "ui",
            "logs",
            "network",
            "security",
            "updates",
            "optimization",
            "enterprise",
            "sandbox",
            "config",
            "drivers",
            "quarantine"
        ]

        # Copy single files
        for file in files_to_copy:
            src = self.project_root / file
            if src.exists():
                dest = self.dist_dir / file
                shutil.copy2(src, dest)
                print(f"    Copied: {file}")

        # Copy directories
        for dir_name in dirs_to_copy:
            src = self.project_root / dir_name
            if src.exists():
                dest = self.dist_dir / dir_name
                shutil.copytree(src, dest)
                print(f"    Copied: {dir_name}/")

        print("[+] Files copied")

    def create_readme(self):
        """Create README for the package"""
        readme_content = f"""# {APP_NAME} v{APP_VERSION}

## Installation

1. Run the installer
2. Follow the installation wizard
3. The application will be installed to: {INSTALL_DIR}

## Features

- Real-time protection
- AI-powered threat detection
- Multiple scan modes
- Privacy protection
- Enterprise features

## Requirements

- Windows 10/11
- 4GB RAM minimum
- 500MB disk space

## Support

Website: {APP_URL}
Email: support@secureguard.example.com

© {datetime.now().year} {APP_PUBLISHER}. All rights reserved.
"""

        readme_path = self.dist_dir / "README.txt"
        with open(readme_path, 'w') as f:
            f.write(readme_content)

        print("[+] README created")

    def create_launcher(self):
        """Create launcher scripts"""

        # Windows batch file
        batch_content = f"""@echo off
cd /d "%~dp0"
python main.py
"""

        batch_path = self.dist_dir / "SecureGuard.bat"
        with open(batch_path, 'w') as f:
            f.write(batch_content)

        # PowerShell script for GUI
        ps1_content = f"""
$ErrorActionPreference = "Stop"
$scriptPath = Split-Path -Parent $MyInvocation.MyCommand.Path
python "$scriptPath\\main.py"
"""

        ps1_path = self.dist_dir / "SecureGuard.ps1"
        with open(ps1_path, 'w') as f:
            f.write(ps1_content)

        print("[+] Launchers created")

    def build_exe(self):
        """Build executable using PyInstaller"""
        print("[*] Building executable with PyInstaller...")

        # Check if PyInstaller is installed
        try:
            import PyInstaller
        except ImportError:
            print("[!] PyInstaller not found, installing...")
            subprocess.run([sys.executable, "-m", "pip",
                           "install", "pyinstaller"], check=True)

        # PyInstaller command
        pyinstaller_cmd = [
            sys.executable, "-m", "PyInstaller",
            "--name=SecureGuard",
            "--onefile",
            "--windowed",
            "--icon=icon.ico",
            "--add-data=engine;engine",
            "--add-data=ai;ai",
            "--add-data=ui;ui",
            "--add-data=logs;logs",
            "--add-data=network;network",
            "--add-data=security;security",
            "--add-data=updates;updates",
            "--add-data=optimization;optimization",
            "--add-data=enterprise;enterprise",
            "--add-data=sandbox;sandbox",
            "--add-data=config;config",
            "--hidden-import=tkinter",
            "--hidden-import=psutil",
            "--hidden-import=cryptography",
            "--collect-all=engine",
            "--collect-all=ai",
            "SecureGuard.py"
        ]

        try:
            subprocess.run(pyinstaller_cmd, check=True)
            print("[+] Executable built successfully")
        except subprocess.CalledProcessError as e:
            print(f"[!] Build failed: {e}")
            return False

        return True

    def create_inno_setup_script(self):
        """Create Inno Setup script for installer"""
        iss_content = '''; SecureGuard Antivirus Installer Script
; Generated for Inno Setup 6.x

#define MyAppName "SecureGuard Antivirus"
#define MyAppVersion "1.0.0"
#define MyAppPublisher "SecureGuard"
#define MyAppURL "https://secureguard.example.com"
#define MyAppExeName "SecureGuard.exe"

[Setup]
AppId={{A1B2C3D4-E5F6-7890-ABCD-EF1234567890}}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
AppPublisherURL={#MyAppURL}
DefaultDirName={pf}\\SecureGuard
DefaultGroupName={#MyAppName}
AllowNoIcons=yes
OutputDir=installer
OutputBaseFilename=SecureGuard-Setup-{#MyAppVersion}
Compression=lzma
SolidCompression=yes
WizardStyle=modern
PrivilegesRequired=admin

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked

[Files]
Source: "dist\\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{group}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"
Name: "{group}\{cm:UninstallProgram,{#MyAppName}}"; Filename: "{uninstallexe}"
Name: "{autodesktop}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; Tasks: desktopicon

[Run]
Filename: "{app}\{#MyAppExeName}"; Description: "{cm:LaunchProgram,{#StringChange(MyAppName, '&', '&&')}}"; Flags: nowait postinstall skipifsilent

[Registry]
Root: HKLM; Subkey: "Software\\Microsoft\\Windows\\CurrentVersion\\Run"; ValueType: string; ValueName: "SecureGuard"; ValueData: """{app}\SecureGuard.exe"""; Flags: uninsdeletevalue

[Code]
function InitializeSetup(): Boolean;
begin
  Result := True;
end;
'''

        iss_path = self.project_root / "SecureGuard.iss"
        with open(iss_path, 'w') as f:
            f.write(iss_content)

        print(f"[+] Inno Setup script created: {iss_path}")
        print("[!] To build installer, install Inno Setup and compile SecureGuard.iss")

    def build(self):
        """Run full build process"""
        print(f"\n{'='*50}")
        print(f"Building {APP_NAME} v{APP_VERSION}")
        print(f"{'='*50}\n")

        # Step 1: Clean
        self.clean()

        # Step 2: Copy files
        self.copy_files()

        # Step 3: Create README
        self.create_readme()

        # Step 4: Create launchers
        self.create_launcher()

        # Step 5: Create installer script
        self.create_inno_setup_script()

        print(f"\n{'='*50}")
        print("Build Complete!")
        print(f"{'='*50}")
        print(f"\nOutput directory: {self.dist_dir}")
        print("\nNext steps:")
        print("1. Install PyInstaller: pip install pyinstaller")
        print("2. Build executable: python build.py exe")
        print("3. Compile installer: Inno Setup SecureGuard.iss")


if __name__ == '__main__':
    builder = BuildManager()

    if len(sys.argv) > 1:
        command = sys.argv[1].lower()

        if command == 'clean':
            builder.clean()
        elif command == 'exe':
            builder.clean()
            builder.copy_files()
            builder.build_exe()
        elif command == 'all':
            builder.build()
        else:
            print("Usage: build.py [clean|exe|all]")
    else:
        builder.build()
