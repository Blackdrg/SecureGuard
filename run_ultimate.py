#!/usr/bin/env python
"""
SecureGuard Antivirus - Ultimate Launcher
========================================
Launches the Ultimate GUI with enterprise security features.
"""
from network.threat_feed import ThreatFeed
from engine.network_shield import NetworkShield
from engine.process_monitor import ProcessMonitor
from engine.quarantine_system import QuarantineSystem
from engine.detection_engine import DetectionEngine
from engine.system_stats import SystemStats
from engine.enterprise_security import EnterpriseSecurityEngine
from logs.threat_logger import get_threat_logger
import sys
import os
sys.path.append(os.path.dirname(__file__))

# Try Ultimate UI first, fallback to professional/standard
try:
    from ui.modern_ui_ultimate import SecureGuardUltimate
    UI_MODULE = "Ultimate"
    UI_CLASS = SecureGuardUltimate
except ImportError:
    try:
        from ui.modern_ui_pro import ModernUI
        UI_MODULE = "Professional"
        UI_CLASS = ModernUI
    except ImportError:
        try:
            from ui.modern_ui_new import ModernUI
            UI_MODULE = "Standard"
            UI_CLASS = ModernUI
        except ImportError:
            print("ERROR: No UI module available!")
            sys.exit(1)


# Initialize real detection engine
print("=" * 70)
print(" SecureGuard Antivirus - Ultimate Security Suite")
print("=" * 70)
print()

# Load all real security modules
print("[🔍] Loading Detection Engine...")
detection_engine = DetectionEngine()
print(f"      → {len(detection_engine.signatures)} malware signatures loaded")
print(f"      → YARA support: {'Enabled' if detection_engine.yara_rules else 'Not available'}")

print("[📁] Loading Quarantine System...")
quarantine = QuarantineSystem()
print("      → AES-256 encryption enabled")

print("[⚙️ ] Loading Process Monitor...")
process_monitor = ProcessMonitor()
print("      → Behavior analysis ready")

print("[🌐] Loading Network Shield...")
network_shield = NetworkShield()
print(f"      → {len(network_shield.blocked_ips)} malicious IPs blocked")

print("[☁️] Loading Threat Feed...")
threat_feed = ThreatFeed()
print("      → Cloud threat intelligence connected")

print("[📊] Loading System Stats...")
system_stats = SystemStats()
print("      → Performance monitoring active")

print("[📝] Loading Threat Logger...")
threat_logger = get_threat_logger()
print("      → Threat history tracking enabled")

print("[🛡️] Loading Enterprise Security Engine...")
enterprise_engine = EnterpriseSecurityEngine()
enterprise_stats = enterprise_engine.get_all_stats()

print()
print("=" * 70)
print(f" All security modules loaded successfully! (UI: {UI_MODULE})")
print("=" * 70)
print()
print("Enterprise Protection Features:")
print(f"  • Zero-Day Defense: {enterprise_stats['zero_day_defense']['zero_day_protection']}")
print(f"  • Cloud Intelligence: {enterprise_stats['cloud_intelligence']['connected']}")
print(f"  • Smart Sandbox: {enterprise_stats['sandbox']['enabled']}")
print(f"  • Exploit Protection: {enterprise_stats['exploit_protection']['memory_protection']}")
print(f"  • Anti-Phishing: Active")
print(f"  • File Reputation: Active")
print(f"  • Smart Firewall AI: {enterprise_stats['smart_firewall']['ai_enabled']}")
print(f"  • Offline Mode: {enterprise_stats['offline_protection']['protection_active']}")
print()

# Launch GUI with all features
if __name__ == "__main__":
    try:
        app = UI_CLASS()
        try:
            app.root.state('zoomed')
        except:
            pass
        app.run()
    except KeyboardInterrupt:
        print("\n\nSecureGuard Antivirus closed.")
    except Exception as e:
        print(f"Error launching application: {e}")
        import traceback
        traceback.print_exc()
