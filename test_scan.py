#!/usr/bin/env python3
"""Debug scanning"""
import sys
import os
sys.path.insert(0, os.path.dirname(__file__))

from engine.detection_engine import DetectionEngine

de = DetectionEngine()

# Get files in current directory
print("Files in current directory:")
for f in os.listdir('.'):
    if os.path.isfile(f):
        print(f"  {f}")

print("\nTrying to scan main.py...")
result = de.scan_file('main.py')
print(f"Result: clean={result['clean']}, threat_name={result.get('threat_name')}")

print("\nTrying to scan detection_engine.py...")
result = de.scan_file('engine/detection_engine.py')
print(f"Result: clean={result['clean']}, threat_name={result.get('threat_name')}")

# Test hash computation
print("\nComputing hash of main.py...")
md5, sha1, sha256 = de.compute_file_hash('main.py')
print(f"MD5: {md5}")
print(f"SHA1: {sha1}")
print(f"SHA256: {sha256[:32]}...")

# Check signature
print(f"\nChecking signature for {md5}...")
threat = de.check_signature(md5)
print(f"Threat match: {threat}")
