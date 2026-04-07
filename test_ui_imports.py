"""Test UI imports"""
import sys
sys.path.append('.')

print("Testing UI module imports...")

# Test UI imports
from ui.modern_ui_new import ModernUI
print("  ModernUI: OK")

# Test all core components
from engine.detection_engine import DetectionEngine
from engine.quarantine_system import QuarantineSystem
from engine.process_monitor import ProcessMonitor
from engine.system_stats import SystemStats
from network.threat_feed import ThreatFeed

print("  DetectionEngine: OK")
print("  QuarantineSystem: OK")
print("  ProcessMonitor: OK")
print("  SystemStats: OK")
print("  ThreatFeed: OK")

print("\nAll imports successful!")
print("\nTo run the GUI, use:")
print("  python SecureGuard.py")
print("  or")
print("  python main.py")
