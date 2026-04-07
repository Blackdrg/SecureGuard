#!/usr/bin/env python
"""
SecureGuard Antivirus - Main Entry Point
"""
import sys
import os

sys.path.append(os.path.dirname(__file__))

if __name__ == "__main__":
    from ui.modern_ui_new import ModernUI
    app = ModernUI()
    app.root.state('zoomed')
    app.run()
