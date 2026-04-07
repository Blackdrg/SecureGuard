#!/usr/bin/env python
"""
SecureGuard Antivirus - Main Launcher
=====================================
This launcher provides a simple menu to choose between different UI options.
"""

import sys
import os

# Add current directory to path
sys.path.insert(0, os.path.dirname(__file__))


def print_banner():
    print("=" * 70)
    print("  SecureGuard Antivirus - Professional Security Suite")
    print("=" * 70)
    print()


def print_menu():
    print("Select an option:")
    print("  [1] Enterprise Dashboard - Advanced UI with radar, threat map")
    print("  [2] Professional Antivirus - Standard protection UI")
    print("  [3] Ultimate Security Suite - All enterprise features")
    print("  [4] Quick GUI - Simple launcher")
    print("  [0] Exit")
    print()


def main():
    print_banner()
    
    while True:
        print_menu()
        choice = input("Enter choice [0-4]: ").strip()
        
        if choice == '1':
            print("\nLoading Enterprise Dashboard...\n")
            from run_dashboard import run_dashboard
            run_dashboard()
            break
        elif choice == '2':
            print("\nLoading Professional Antivirus...\n")
            from run_antivirus import run_antivirus
            run_antivirus()
            break
        elif choice == '3':
            print("\nLoading Ultimate Security Suite...\n")
            from run_ultimate import run_ultimate
            run_ultimate()
            break
        elif choice == '4':
            print("\nLoading Quick GUI...\n")
            from run_gui import run_gui
            run_gui()
            break
        elif choice == '0':
            print("\nExiting SecureGuard. Stay safe!")
            break
        else:
            print("\nInvalid choice. Please try again.\n")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\nExiting SecureGuard. Stay safe!")
    except Exception as e:
        print(f"\nError: {e}")
        input("\nPress Enter to exit...")
