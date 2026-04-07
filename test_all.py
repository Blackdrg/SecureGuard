#!/usr/bin/env python
"""Test all SecureGuard features"""
import sys
sys.path.insert(0, '.')

print('=== SecureGuard Complete Feature Test ===')
print()

# Test all launchers
launchers = [
    ('run_dashboard.py', 'Enterprise Dashboard'),
    ('run_cyber.py', 'Cyber Dashboard'),
    ('run_antivirus.py', 'Professional Antivirus'),
    ('run_ultimate.py', 'Ultimate Security'),
    ('run_gui.py', 'Quick GUI'),
]

print('Testing Launchers:')
for file, name in launchers:
    try:
        with open(file) as f:
            content = f.read()
        print(f'  [OK] {name} ({file})')
    except Exception as e:
        print(f'  [FAIL] {name}: {e}')

print()
print('Testing UI Modules:')
ui_modules = [
    ('ui.enterprise_dashboard', 'Enterprise Dashboard UI'),
    ('ui.cyber_dashboard', 'Cyber Dashboard UI'),
    ('ui.modern_ui_new', 'Modern UI'),
]

for mod, name in ui_modules:
    try:
        __import__(mod)
        print(f'  [OK] {name}')
    except Exception as e:
        print(f'  [FAIL] {name}: {e}')

print()
print('Testing Core Modules:')
core_modules = [
    ('engine.detection_engine', 'Detection Engine'),
    ('engine.quarantine_system', 'Quarantine'),
    ('engine.process_monitor', 'Process Monitor'),
    ('engine.network_shield', 'Network Shield'),
    ('engine.system_stats', 'System Stats'),
    ('ai.behavior_analyzer', 'Behavior Analyzer'),
    ('ai.ml_detector', 'ML Detector'),
]

for mod, name in core_modules:
    try:
        __import__(mod)
        print(f'  [OK] {name}')
    except Exception as e:
        print(f'  [FAIL] {name}: {e}')

print()
print('=== All Tests Complete ===')
