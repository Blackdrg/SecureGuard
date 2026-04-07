"""
SecureGuard Antivirus - Behavior Monitor
========================================

Monitors program behavior for suspicious activities.
"""

import os
import sys
import time
import threading
import psutil
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Any, Optional


class BehaviorMonitor:
    """Monitors program behavior for suspicious activities"""
    
    # Suspicious behaviors to monitor
    SUSPICIOUS_BEHAVIORS = [
        'mass_file_delete',
        'mass_file_encrypt',
        'suspicious_process_spawn',
        'privilege_escalation',
        'registry_modification',
        'network_connection',
    ]
    
    def __init__(self, threat_logger=None):
        self.running = False
        self.monitor_thread = None
        self.threat_logger = threat_logger
        self.suspicious_processes = []
        self.alert_callback = None
        
        print("[*] Behavior Monitor initialized")
    
    def set_alert_callback(self, callback):
        """Set callback for alerts"""
        self.alert_callback = callback
    
    def start_monitoring(self):
        """Start behavior monitoring"""
        if self.running:
            return
        
        self.running = True
        self.monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self.monitor_thread.start()
        
        print("[+] Behavior Monitor started")
    
    def stop(self):
        """Stop behavior monitoring"""
        self.running = False
        if self.monitor_thread:
            self.monitor_thread.join(timeout=5)
        
        print("[-] Behavior Monitor stopped")
    
    def _monitor_loop(self):
        """Main monitoring loop"""
        while self.running:
            try:
                self._check_process_behavior()
            except Exception as e:
                print(f"[!] Behavior monitor error: {e}")
            
            time.sleep(2)
    
    def _check_process_behavior(self):
        """Check behavior of running processes"""
        try:
            for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
                try:
                    info = proc.info
                    name = info.get('name', '').lower()
                    
                    # Check for suspicious process names
                    suspicious = ['mimikatz', 'procdump', 'lsass']
                    if any(s in name for s in suspicious):
                        self._alert_suspicious_process(info)
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
        except:
            pass
    
    def _alert_suspicious_process(self, process_info):
        """Alert about suspicious process"""
        print(f"[!] Suspicious process detected: {process_info.get('name')}")
        
        if self.alert_callback:
            self.alert_callback({
                'type': 'suspicious_process',
                'process': process_info
            })
    
    def get_status(self) -> Dict[str, Any]:
        """Get monitor status"""
        return {
            'running': self.running,
            'monitored_behaviors': len(self.SUSPICIOUS_BEHAVIORS)
        }
