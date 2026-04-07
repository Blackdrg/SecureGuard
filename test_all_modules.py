"""Test all core modules"""
from engine.detection_engine import DetectionEngine
from engine.quarantine_system import QuarantineSystem
from engine.process_monitor import ProcessMonitor
from engine.system_stats import SystemStats
from network.threat_feed import ThreatFeed

print('Testing DetectionEngine...')
de = DetectionEngine()
print(f'  Signatures loaded: {len(de.signatures)}')
print(f'  Files scanned: {de.files_scanned}')
print(f'  Threats detected: {de.threats_detected}')

print('Testing QuarantineSystem...')
qs = QuarantineSystem()
print(f'  Quarantined items: {qs.get_quarantined_count()}')

print('Testing ProcessMonitor...')
pm = ProcessMonitor()
procs = pm.get_all_processes()
print(f'  Running processes: {len(procs)}')
susp = pm.scan_processes()
print(f'  Suspicious processes: {len(susp)}')

print('Testing SystemStats...')
ss = SystemStats()
stats = ss.get_all_stats()
print(f'  System stats retrieved: {bool(stats)}')

print('Testing ThreatFeed...')
tf = ThreatFeed()
print(f'  Threat feed loaded: {bool(tf)}')

print('\nAll core modules working!')
