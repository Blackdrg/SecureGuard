"""
SecureGuard Antivirus - Ransomware Protection
=============================================

Advanced ransomware protection with file integrity monitoring.
"""

import os
import sys
import time
import threading
import hashlib
from pathlib import Path
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional


class FileIntegrityMonitor:
    """Monitors file integrity to detect ransomware activity"""
    
    def __init__(self):
        self.monitored_files = {}
        self.baseline_hashes = {}
        
    def add_path(self, path: str):
        """Add a path to monitor"""
        try:
            p = Path(path)
            if p.exists():
                if p.is_file():
                    self.monitored_files[str(p)] = p.stat().st_mtime
                elif p.is_dir():
                    for f in p.rglob('*'):
                        if f.is_file():
                            self.monitored_files[str(f)] = f.stat().st_mtime
        except Exception as e:
            print(f"[!] Error adding path {path}: {e}")
    
    def check_integrity(self) -> List[str]:
        """Check for file changes"""
        changed = []
        for file_path, last_mtime in list(self.monitored_files.items()):
            try:
                if os.path.exists(file_path):
                    current_mtime = os.path.getmtime(file_path)
                    if current_mtime > last_mtime:
                        changed.append(file_path)
            except:
                pass
        return changed


class RansomwareProtection:
    """Advanced ransomware protection"""
    
    def __init__(self, threat_logger=None):
        self.running = False
        self.protect_thread = None
        self.threat_logger = threat_logger
        self.file_monitor = FileIntegrityMonitor()
        self.alert_callback = None
        
        # Initialize monitored paths
        self._init_monitored_paths()
        
        print("[*] Ransomware Protection initialized")
    
    def _init_monitored_paths(self):
        """Initialize paths to monitor"""
        paths = [
            os.path.expanduser("~/Documents"),
            os.path.expanduser("~/Desktop"),
            os.path.expanduser("~/Pictures"),
        ]
        
        for path in paths:
            if os.path.exists(path):
                self.file_monitor.add_path(path)
    
    def set_alert_callback(self, callback):
        """Set callback for alerts"""
        self.alert_callback = callback
    
    def start_protection(self):
        """Start ransomware protection"""
        if self.running:
            return
        
        self.running = True
        self.protect_thread = threading.Thread(target=self._protect_loop, daemon=True)
        self.protect_thread.start()
        
        print("[+] Ransomware Protection started")
    
    def stop(self):
        """Stop ransomware protection"""
        self.running = False
        if self.protect_thread:
            self.protect_thread.join(timeout=5)
        
        print("[-] Ransomware Protection stopped")
    
    def _protect_loop(self):
        """Main protection loop"""
        while self.running:
            try:
                # Check file integrity
                changed_files = self.file_monitor.check_integrity()
                
                if changed_files:
                    # Check if too many files changed (ransomware behavior)
                    if len(changed_files) > 10:
                        self._alert_ransomware(changed_files)
                        
            except Exception as e:
                print(f"[!] Ransomware protection error: {e}")
            
            time.sleep(2)
    
    def _alert_ransomware(self, files: List[str]):
        """Alert about potential ransomware"""
        print(f"[!] ALERT: Possible ransomware activity detected!")
        print(f"    Files affected: {len(files)}")
        
        if self.alert_callback:
            self.alert_callback({
                'type': 'ransomware',
                'files': files[:10]  # First 10 files
            })
    
    def get_status(self) -> Dict[str, Any]:
        """Get protection status"""
        return {
            'running': self.running,
            'monitored_files': len(self.file_monitor.monitored_files)
        }
