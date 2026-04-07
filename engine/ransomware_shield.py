"""
SecureGuard Antivirus - Ransomware Shield
==========================================

Protection against ransomware attacks.
"""

import os
import sys
import time
import threading
from pathlib import Path
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional


class RansomwareShield:
    """Protects against ransomware attacks"""
    
    # Known ransomware file extensions
    RANSOMWARE_EXTENSIONS = [
        '.encrypted', '.locked', '.crypto', '.crypt', '.enc',
        '.locked', '.xyz', '.abc', '.vvv', '.ccc', '.ddd', '.eee',
        '.encrypted', '.encryped', '.crypt1', '.crypt2'
    ]
    
    # Protected folders
    PROTECTED_FOLDERS = [
        os.path.expanduser("~/Documents"),
        os.path.expanduser("~/Desktop"),
        os.path.expanduser("~/Pictures"),
        os.path.expanduser("~/Videos"),
        "C:\\Users\\Public\\Documents",
    ]
    
    def __init__(self):
        self.running = False
        self.monitor_thread = None
        self.protected_paths = []
        self.suspicious_processes = []
        self.alert_callback = None
        
        # Initialize protected paths
        self._init_protected_paths()
        
        print("[*] Ransomware Shield initialized")
    
    def _init_protected_paths(self):
        """Initialize list of protected paths"""
        for folder in self.PROTECTED_FOLDERS:
            if os.path.exists(folder):
                self.protected_paths.append(folder)
    
    def set_alert_callback(self, callback):
        """Set callback for alerts"""
        self.alert_callback = callback
    
    def add_protected_path(self, path: str):
        """Add a path to protect"""
        if os.path.exists(path) and path not in self.protected_paths:
            self.protected_paths.append(path)
    
    def remove_protected_path(self, path: str):
        """Remove a path from protection"""
        if path in self.protected_paths:
            self.protected_paths.remove(path)
    
    def start_monitoring(self):
        """Start ransomware monitoring"""
        if self.running:
            return
        
        self.running = True
        self.monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self.monitor_thread.start()
        
        print(f"[+] Ransomware Shield active - protecting {len(self.protected_paths)} folders")
    
    def stop_monitoring(self):
        """Stop ransomware monitoring"""
        self.running = False
        if self.monitor_thread:
            self.monitor_thread.join(timeout=5)
        
        print("[-] Ransomware Shield stopped")
    
    def _monitor_loop(self):
        """Main monitoring loop"""
        last_check = datetime.now()
        
        while self.running:
            try:
                # Check for suspicious activity
                self._check_file_activity()
                self._check_process_activity()
                
                # Wait a bit between checks
                time.sleep(2)
                
            except Exception as e:
                print(f"[!] Ransomware monitor error: {e}")
                time.sleep(5)
    
    def _check_file_activity(self):
        """Check for suspicious file encryption activity"""
        # In production, this would monitor for:
        # - Rapid file modification in protected folders
        # - New encrypted file extensions
        # - Large number of files being modified at once
        
        # Simplified version - just scan for known ransomware extensions
        for path in self.protected_paths:
            if not os.path.exists(path):
                continue
            
            try:
                # Check for known ransomware extensions
                for ext in self.RANSOMWARE_EXTENSIONS:
                    ransomware_files = list(Path(path).glob(f"**/*{ext}"))
                    if ransomware_files:
                        self._alert_ransomware(path, ext, len(ransomware_files))
            except:
                pass
    
    def _check_process_activity(self):
        """Check for suspicious ransomware processes"""
        try:
            import psutil
            
            # Known ransomware process names
            suspicious_names = [
                'vCrypt', 'Ransomware', 'Cerber', 'Locky', 'CryptoLocker',
                'WannaCry', 'Petya', 'NotPetya', 'BadRabbit'
            ]
            
            for proc in psutil.process_iter(['name']):
                try:
                    proc_name = proc.info['name'].lower()
                    if any(s.lower() in proc_name for s in suspicious_names):
                        self._alert_suspicious_process(proc.info['name'])
                except:
                    pass
        except ImportError:
            pass
    
    def _alert_ransomware(self, path: str, extension: str, count: int):
        """Alert when ransomware activity detected"""
        print(f"[!] ALERT: Potential ransomware detected!")
        print(f"    Path: {path}")
        print(f"    Extension: {extension}")
        print(f"    Files affected: {count}")
        
        if self.alert_callback:
            self.alert_callback({
                'type': 'ransomware',
                'path': path,
                'extension': extension,
                'count': count
            })
    
    def _alert_suspicious_process(self, process_name: str):
        """Alert when suspicious process detected"""
        print(f"[!] ALERT: Suspicious process: {process_name}")
        
        if self.alert_callback:
            self.alert_callback({
                'type': 'suspicious_process',
                'process': process_name
            })
    
    def get_status(self) -> Dict[str, Any]:
        """Get shield status"""
        return {
            'running': self.running,
            'protected_paths': self.protected_paths,
            'protected_count': len(self.protected_paths)
        }
    
    def check_file(self, file_path: str) -> bool:
        """Check if a file is a known ransomware file"""
        path = Path(file_path)
        
        # Check extension
        if path.suffix.lower() in self.RANSOMWARE_EXTENSIONS:
            return True
        
        return False


# Singleton instance
_ransomware_shield = None

def get_ransomware_shield():
    """Get singleton RansomwareShield instance"""
    global _ransomware_shield
    if _ransomware_shield is None:
        _ransomware_shield = RansomwareShield()
    return _ransomware_shield
