#!/usr/bin/env python
"""
SecureGuard Antivirus - Cyber Dashboard Launcher
==============================================
Launches the enhanced Cyber Dashboard with advanced graphics.
"""
import sys
import os
sys.path.append(os.path.dirname(__file__))

# Patch tkinter for rounded rectangles
import tkinter as tk

def create_rounded_rectangle(self, x1, y1, x2, y2, radius=25, **kwargs):
    """Create a rounded rectangle"""
    points = [
        x1 + radius, y1,
        x2 - radius, y1,
        x2, y1,
        x2, y1 + radius,
        x2, y2 - radius,
        x2, y2,
        x2 - radius, y2,
        x1 + radius, y2,
        x1, y2,
        x1, y2 - radius,
        x1, y1 + radius,
        x1, y1
    ]
    return self.create_polygon(points, **kwargs)

# Apply patch
tk.Canvas.create_rounded_rectangle = create_rounded_rectangle

# Now import and run
print("=" * 70)
print(" SecureGuard Antivirus - Cyber Defense Center")
print("=" * 70)
print()

print("[🔒] Loading Security Modules...")
from engine.detection_engine import DetectionEngine
from engine.quarantine_system import QuarantineSystem
from engine.process_monitor import ProcessMonitor
from engine.network_shield import NetworkShield

detection = DetectionEngine()
print(f"      → {len(detection.signatures)} threat signatures loaded")

print("[🛡️] Initializing Cyber Defense Systems...")

print()
print("=" * 70)
print(" Launching Cyber Dashboard...")
print("=" * 70)
print()

if __name__ == "__main__":
    try:
        from ui.cyber_dashboard import CyberDashboard
        app = CyberDashboard()
        app.mainloop()
    except KeyboardInterrupt:
        print("\n\nSecureGuard Cyber Dashboard closed.")
    except Exception as e:
        print(f"Error launching dashboard: {e}")
        import traceback
        traceback.print_exc()
