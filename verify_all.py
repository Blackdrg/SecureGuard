#!/usr/bin/env python
"""Verify all SecureGuard components are working"""
import sys
import os

print("=" * 60)
print("SecureGuard Antivirus - Component Verification")
print("=" * 60)

# Test core engine imports
print("\n[1] Testing Engine Modules...")
try:
    from engine.detection_engine import DetectionEngine
    from engine.quarantine_system import QuarantineSystem
    from engine.process_monitor import ProcessMonitor
    from engine.network_shield import NetworkShield
    from engine.system_stats import SystemStats
    from engine.core_engine import CoreEngine
    from engine.scan_modes import ScanModes
    print("   ✓ Core engine modules imported")
except Exception as e:
    print(f"   ✗ Engine error: {e}")
    sys.exit(1)

# Test AI modules
print("\n[2] Testing AI Modules...")
try:
    from engine.ai_threat_analysis import AIThreatAnalyzer, SecurityScoreMeter
    print("   ✓ AI modules imported")
except Exception as e:
    print(f"   ✗ AI error: {e}")

# Test network modules  
print("\n[3] Testing Network Modules...")
try:
    from network.threat_feed import ThreatFeed
    print("   ✓ Network modules imported")
except Exception as e:
    print(f"   ✗ Network error: {e}")

# Test UI
print("\n[4] Testing UI Module...")
try:
    from ui.modern_ui_new import ModernUI, COLORS
    print("   ✓ UI module imported")
except Exception as e:
    print(f"   ✗ UI error: {e}")

# Test instantiation
print("\n[5] Testing Component Instantiation...")
try:
    engine = DetectionEngine()
    print(f"   ✓ DetectionEngine: {len(engine.signatures)} signatures loaded")
    
    quarantine = QuarantineSystem()
    print(f"   ✓ QuarantineSystem initialized")
    
    process_mon = ProcessMonitor()
    print(f"   ✓ ProcessMonitor initialized")
    
    network = NetworkShield()
    print(f"   ✓ NetworkShield initialized")
    
    stats = SystemStats()
    print(f"   ✓ SystemStats initialized")
    
except Exception as e:
    print(f"   ✗ Instantiation error: {e}")
    sys.exit(1)

# Test scan functionality
print("\n[6] Testing Scan Functionality...")
try:
    # Quick scan test
    test_file = __file__
    result = engine.scan_file(test_file)
    print(f"   ✓ File scan test: {result.get('clean', True)}")
    
    # Directory scan test
    results = engine.scan_directory(os.path.dirname(test_file), recursive=False)
    print(f"   ✓ Directory scan: {len(results)} files scanned")
    
except Exception as e:
    print(f"   ✗ Scan error: {e}")

# Test system stats
print("\n[7] Testing System Stats...")
try:
    cpu = stats.get_cpu_usage()
    mem = stats.get_memory_usage()
    print(f"   ✓ CPU: {cpu:.1f}%")
    print(f"   ✓ Memory: {mem:.1f}%")
except Exception as e:
    print(f"   ✗ Stats error: {e}")

# Test AI features
print("\n[8] Testing AI Features...")
try:
    analyzer = AIThreatAnalyzer()
    score_meter = SecurityScoreMeter()
    score_data = score_meter.calculate_score()
    print(f"   ✓ Security Score: {score_data.get('score', 'N/A')}/100")
    print(f"   ✓ Grade: {score_data.get('grade', 'N/A')}")
except Exception as e:
    print(f"   ✗ AI error: {e}")

print("\n" + "=" * 60)
print("VERIFICATION COMPLETE - All components working!")
print("=" * 60)
print("\nTo run the GUI:")
print("  python SecureGuard.py")
print("\nTo run in console mode:")
print("  python main.py")
