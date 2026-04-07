#!/usr/bin/env python
"""
SecureGuard Antivirus - Build Executable
======================================
Creates a standalone .exe file using PyInstaller.
"""

import os
import sys
import subprocess

def install_pyinstaller():
    """Install PyInstaller if not present"""
    try:
        import PyInstaller
        print("[*] PyInstaller already installed")
        return True
    except ImportError:
        print("[*] Installing PyInstaller...")
        subprocess.check_call([sys.executable, "-m", "pip", "install", "pyinstaller"])
        return True

def build_exe():
    """Build the executable"""
    print("=" * 60)
    print("Building SecureGuard Antivirus .exe")
    print("=" * 60)
    print()
    
    # PyInstaller command
    cmd = [
        sys.executable, "-m", "PyInstaller",
        "--name=SecureGuard",
        "--onefile",
        "--windowed",
        "--icon=NONE",
        "--add-data=engine;engine",
        "--add-data=ai;ai",
        "--add-data=ui;ui",
        "--add-data=logs;logs",
        "--add-data=network;network",
        "--add-data=config;config",
        "--hidden-import=tkinter",
        "--hidden-import=tkinter.ttk",
        "--hidden-import=tkinter.messagebox",
        "--hidden-import=tkinter.filedialog",
        "--collect-all=engine",
        "--collect-all=ai",
        "--collect-all=network",
        "run_all_in_one.py"
    ]
    
    print("[*] Running PyInstaller...")
    print()
    
    try:
        subprocess.check_call(cmd)
        print()
        print("=" * 60)
        print("Build Complete!")
        print("=" * 60)
        print()
        print("Executable location: dist/SecureGuard.exe")
        print()
    except subprocess.CalledProcessError as e:
        print(f"[!] Build failed with error code: {e.returncode}")
        print("[*] Trying alternative build method...")
        
        # Try simpler command
        simple_cmd = [
            sys.executable, "-m", "PyInstaller",
            "--onefile",
            "--windowed",
            "--name=SecureGuard",
            "run_all_in_one.py"
        ]
        
        try:
            subprocess.check_call(simple_cmd)
            print()
            print("Build complete! Executable: dist/SecureGuard.exe")
        except Exception as e2:
            print(f"[!] Alternative build also failed: {e2}")

if __name__ == "__main__":
    install_pyinstaller()
    build_exe()
