"""
SecureGuard Antivirus - Enterprise Dashboard Launcher
==================================================
Launches the Futuristic Enterprise Dashboard with all visual elements.
"""
import sys
import os
sys.path.append(os.path.dirname(__file__))

from network.threat_feed import ThreatFeed
from engine.network_shield import NetworkShield
from engine.process_monitor import ProcessMonitor
from engine.quarantine_system import QuarantineSystem
from engine.detection_engine import DetectionEngine
from engine.system_stats import SystemStats
from engine.enterprise_security import EnterpriseSecurityEngine
from logs.threat_logger import get_threat_logger

print("=" * 70)
print(" SecureGuard Antivirus - Enterprise Dashboard")
print("=" * 70)
print()

# Load all security modules
print("[🔍] Loading Detection Engine...")
detection_engine = DetectionEngine()
print(f"      → {len(detection_engine.signatures)} malware signatures loaded")

print("[📁] Loading Quarantine System...")
quarantine = QuarantineSystem()

print("[⚙️ ] Loading Process Monitor...")
process_monitor = ProcessMonitor()

print("[🌐] Loading Network Shield...")
network_shield = NetworkShield()

print("[☁️] Loading Threat Feed...")
threat_feed = ThreatFeed()

print("[📊] Loading System Stats...")
system_stats = SystemStats()

print("[🛡️] Loading Enterprise Security...")
enterprise_engine = EnterpriseSecurityEngine()

print()
print("=" * 70)
print(" Loading Enterprise Dashboard...")
print("=" * 70)
print()

# Launch Dashboard
if __name__ == "__main__":
    try:
        from ui.enterprise_dashboard import FuturisticDashboard
        app = FuturisticDashboard()
        app.mainloop()
    except KeyboardInterrupt:
        print("\n\nSecureGuard Dashboard closed.")
    except Exception as e:
        print(f"Error launching dashboard: {e}")
        import traceback
        traceback.print_exc()
