#!/usr/bin/env python
"""
SecureGuard Antivirus - Simple GUI Launcher
==========================================
Launches the SecureGuard GUI with all features.
"""

import sys
import os

# Add current directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def main():
    print("=" * 60)
    print("SecureGuard Antivirus - Starting...")
    print("=" * 60)
    
    try:
        from ui.modern_ui_new import ModernUI
        print("[✓] UI Module loaded successfully")
        
        # Launch the GUI
        print("[✓] Starting SecureGuard GUI...")
        app = ModernUI()
        app.run()
        
    except ImportError as e:
        print(f"[✗] Import error: {e}")
        print("\nTrying alternative launcher...")
        
        # Try the simpler SecureGuard.py
        try:
            from SecureGuard import main as secureguard_main
            secureguard_main()
        except Exception as e2:
            print(f"[✗] Alternative also failed: {e2}")
            sys.exit(1)
    
    except Exception as e:
        print(f"[✗] Error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()
