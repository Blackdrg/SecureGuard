#!/usr/bin/env python3
"""Test core components"""
import sys
import os
sys.path.append(os.path.dirname(__file__))

from engine.detection_engine import DetectionEngine
from engine.quarantine_system import QuarantineSystem
from engine.process_monitor import ProcessMonitor
from engine.network_shield import NetworkShield

print("=" * 60)
print("SecureGuard - Core Components Test")
print("=" * 60)

# Test detection engine
print("\n[*] Testing Detection Engine...")
de = DetectionEngine()
print(f"    Signatures loaded: {len(de.signatures)}")
print("    OK")

# Test quarantine
print("\n[*] Testing Quarantine System...")
qs = QuarantineSystem()
print(f"    Quarantined items: {qs.get_quarantined_count()}")
print("    OK")

# Test process monitor
print("\n[*] Testing Process Monitor...")
pm = ProcessMonitor()
procs = pm.get_all_processes()
print(f"    Running processes: {len(procs)}")
suspicious = pm.scan_processes()
print(f"    Suspicious processes: {len(suspicious)}")
print("    OK")

# Test network shield
print("\n[*] Testing Network Shield...")
ns = NetworkShield()
print(f"    Blocked IPs: {len(ns.blocked_ips)}")
print("    OK")

print("\n" + "=" * 60)
print("All core components working!")
print("=" * 60)
