"""
SecureGuard Antivirus - Core Engine
====================================

The core engine that orchestrates all antivirus operations.
"""

import os
import sys
import time
import threading
import queue
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Optional, Any

# Import existing modules
from engine.quarantine_system import QuarantineSystem
from engine.system_stats import SystemStats


class CoreEngine:
    """Core engine for SecureGuard Antivirus"""
    
    def __init__(self):
        self.running = False
        self.protection_enabled = True
        self.scan_queue = queue.Queue()
        self.workers = []
        self.num_workers = 4
        
        # Initialize core components
        self.quarantine = QuarantineSystem()
        self.stats = SystemStats()
        
        # Detection cache
        self.detection_cache = {}
        self.cache_size = 1000
        
        # Statistics
        self.total_scans = 0
        self.threats_detected = 0
        self.files_scanned = 0
        self.start_time = None
        
        print("[*] Core Engine initialized")
    
    def start_realtime_protection(self):
        """Start real-time protection"""
        if self.running:
            return
        
        self.running = True
        self.start_time = datetime.now()
        
        # Start worker threads
        for i in range(self.num_workers):
            worker = threading.Thread(target=self._worker, daemon=True)
            worker.start()
            self.workers.append(worker)
        
        print(f"[+] Core Engine started with {self.num_workers} workers")
    
    def stop(self):
        """Stop the core engine"""
        self.running = False
        
        # Wait for workers to finish
        for worker in self.workers:
            worker.join(timeout=2)
        
        self.workers.clear()
        
        if self.start_time:
            uptime = datetime.now() - self.start_time
            print(f"[-] Core Engine stopped (uptime: {uptime})")
    
    def _worker(self):
        """Worker thread for processing scan queue"""
        while self.running:
            try:
                task = self.scan_queue.get(timeout=1)
                if task is None:
                    break
                
                file_path = task.get('path')
                if file_path:
                    self._scan_file(file_path)
                
                self.scan_queue.task_done()
            except queue.Empty:
                continue
            except Exception as e:
                print(f"[!] Worker error: {e}")
    
    def _scan_file(self, file_path: str) -> Dict[str, Any]:
        """Scan a single file"""
        self.files_scanned += 1
        
        result = {
            'path': file_path,
            'threat': None,
            'clean': True
        }
        
        # Check cache first
        if file_path in self.detection_cache:
            return self.detection_cache[file_path]
        
        try:
            path = Path(file_path)
            if not path.exists():
                return result
            
            # Basic file analysis
            if path.is_file():
                # Check file extension
                ext = path.suffix.lower()
                
                # Dangerous extensions
                dangerous_exts = ['.exe', '.dll', '.bat', '.cmd', '.ps1', 
                                '.vbs', '.js', '.jse', '.wsf', '.wsh', '.scr']
                
                if ext in dangerous_exts:
                    # In production, this would run actual detection
                    # For now, we just note it's a potentially dangerous type
                    pass
                
        except Exception as e:
            print(f"[!] Scan error for {file_path}: {e}")
        
        return result
    
    def queue_scan(self, file_path: str):
        """Add file to scan queue"""
        self.scan_queue.put({'path': file_path})
    
    def scan_directory(self, directory: str, recursive: bool = True) -> List[Dict]:
        """Scan a directory"""
        results = []
        
        try:
            path = Path(directory)
            if not path.exists():
                return results
            
            if recursive:
                files = path.rglob('*')
            else:
                files = path.glob('*')
            
            for file_path in files:
                if file_path.is_file():
                    result = self._scan_file(str(file_path))
                    results.append(result)
                    if not result['clean']:
                        self.threats_detected += 1
                    
                    self.total_scans += 1
            
        except Exception as e:
            print(f"[!] Directory scan error: {e}")
        
        return results
    
    def get_stats(self) -> Dict[str, Any]:
        """Get engine statistics"""
        uptime = None
        if self.start_time:
            uptime = (datetime.now() - self.start_time).total_seconds()
        
        return {
            'running': self.running,
            'protection_enabled': self.protection_enabled,
            'total_scans': self.total_scans,
            'threats_detected': self.threats_detected,
            'files_scanned': self.files_scanned,
            'uptime_seconds': uptime,
            'queue_size': self.scan_queue.qsize(),
            'workers': len(self.workers)
        }
    
    def enable_protection(self):
        """Enable real-time protection"""
        self.protection_enabled = True
        print("[+] Protection enabled")
    
    def disable_protection(self):
        """Disable real-time protection"""
        self.protection_enabled = False
        print("[-] Protection disabled")
    
    def clear_cache(self):
        """Clear detection cache"""
        self.detection_cache.clear()
        print("[*] Detection cache cleared")
    
    def add_to_cache(self, file_path: str, result: Dict):
        """Add result to detection cache"""
        if len(self.detection_cache) >= self.cache_size:
            # Remove oldest entry
            oldest = next(iter(self.detection_cache))
            del self.detection_cache[oldest]
        
        self.detection_cache[file_path] = result


# Singleton instance
_core_engine = None

def get_core_engine():
    """Get singleton CoreEngine instance"""
    global _core_engine
    if _core_engine is None:
        _core_engine = CoreEngine()
    return _core_engine
