"""
SecureGuard Antivirus - Scan Modes
===================================

Provides different scanning modes (quick, full, custom, boot).
"""

import os
import time
import threading
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Any, Callable, Optional

from engine.detection_engine import DetectionEngine
from engine.quarantine_system import QuarantineSystem


class ScanResult:
    """Results of a scan operation"""
    
    def __init__(self):
        self.files_scanned = 0
        self.threats_found = 0
        self.threats = []
        self.duration = 0
        self.start_time = None
        self.end_time = None
        self.scan_type = ""
        self.paths_scanned = []


class ScanModes:
    """Different scan modes for the antivirus"""
    
    # Quick scan paths (common malware locations)
    quick_scan_paths = [
        os.path.expanduser("~/Downloads"),
        os.path.expanduser("~/Documents"),
        os.path.expanduser("~/Desktop"),
        "C:\\Users\\Public\\Downloads",
    ]
    
    def __init__(self, detection_engine: DetectionEngine, 
                 quarantine_system: QuarantineSystem, 
                 threat_logger=None):
        self.detection_engine = detection_engine
        self.quarantine_system = quarantine_system
        self.threat_logger = threat_logger
        self.running = False
        
        print("[*] Scan Modes initialized")
    
    def quick_scan(self, callback: Optional[Callable] = None) -> ScanResult:
        """Perform a quick scan of common locations"""
        print("[*] Starting quick scan...")
        result = ScanResult()
        result.start_time = datetime.now()
        result.scan_type = "quick"
        
        start_time = time.time()
        
        for path in self.quick_scan_paths:
            if not os.path.exists(path):
                continue
            
            result.paths_scanned.append(path)
            
            try:
                scan_results = self.detection_engine.scan_directory(
                    path, recursive=True, quarantine=True, callback=callback
                )
                
                result.files_scanned += len(scan_results)
                
                for scan_result in scan_results:
                    if not scan_result.get('clean', True):
                        result.threats_found += 1
                        result.threats.append(scan_result)
                        
            except Exception as e:
                print(f"[!] Quick scan error on {path}: {e}")
        
        result.end_time = datetime.now()
        result.duration = time.time() - start_time
        
        print(f"[+] Quick scan complete: {result.files_scanned} files, {result.threats_found} threats")
        return result
    
    def full_scan(self, callback: Optional[Callable] = None) -> ScanResult:
        """Perform a full system scan"""
        print("[*] Starting full scan...")
        result = ScanResult()
        result.start_time = datetime.now()
        result.scan_type = "full"
        
        start_time = time.time()
        
        # Scan all drives
        drives = self._get_drives()
        
        for drive in drives:
            result.paths_scanned.append(drive)
            
            try:
                scan_results = self.detection_engine.scan_directory(
                    drive, recursive=True, quarantine=True, callback=callback
                )
                
                result.files_scanned += len(scan_results)
                
                for scan_result in scan_results:
                    if not scan_result.get('clean', True):
                        result.threats_found += 1
                        result.threats.append(scan_result)
                        
            except Exception as e:
                print(f"[!] Full scan error on {drive}: {e}")
        
        result.end_time = datetime.now()
        result.duration = time.time() - start_time
        
        print(f"[+] Full scan complete: {result.files_scanned} files, {result.threats_found} threats")
        return result
    
    def custom_scan(self, paths: List[str], callback: Optional[Callable] = None) -> ScanResult:
        """Scan custom paths"""
        print(f"[*] Starting custom scan of {len(paths)} paths...")
        result = ScanResult()
        result.start_time = datetime.now()
        result.scan_type = "custom"
        
        start_time = time.time()
        
        for path in paths:
            if not os.path.exists(path):
                continue
            
            result.paths_scanned.append(path)
            
            try:
                if os.path.isfile(path):
                    scan_result = self.detection_engine.scan_file(path, quarantine=True)
                    result.files_scanned += 1
                    if not scan_result.get('clean', True):
                        result.threats_found += 1
                        result.threats.append(scan_result)
                else:
                    scan_results = self.detection_engine.scan_directory(
                        path, recursive=True, quarantine=True, callback=callback
                    )
                    result.files_scanned += len(scan_results)
                    
                    for scan_result in scan_results:
                        if not scan_result.get('clean', True):
                            result.threats_found += 1
                            result.threats.append(scan_result)
                            
            except Exception as e:
                print(f"[!] Custom scan error on {path}: {e}")
        
        result.end_time = datetime.now()
        result.duration = time.time() - start_time
        
        print(f"[+] Custom scan complete: {result.files_scanned} files, {result.threats_found} threats")
        return result
    
    def boot_scan(self, callback: Optional[Callable] = None) -> ScanResult:
        """Scan critical system files (boot scan)"""
        print("[*] Starting boot scan...")
        result = ScanResult()
        result.start_time = datetime.now()
        result.scan_type = "boot"
        
        start_time = time.time()
        
        # Critical system paths
        boot_paths = [
            "C:\\Windows\\System32",
            "C:\\Windows\\SysWOW64",
            "C:\\Windows\\System32\\drivers",
        ]
        
        for path in boot_paths:
            if not os.path.exists(path):
                continue
            
            result.paths_scanned.append(path)
            
            try:
                scan_results = self.detection_engine.scan_directory(
                    path, recursive=True, quarantine=True, callback=callback
                )
                
                result.files_scanned += len(scan_results)
                
                for scan_result in scan_results:
                    if not scan_result.get('clean', True):
                        result.threats_found += 1
                        result.threats.append(scan_result)
                        
            except Exception as e:
                print(f"[!] Boot scan error on {path}: {e}")
        
        result.end_time = datetime.now()
        result.duration = time.time() - start_time
        
        print(f"[+] Boot scan complete: {result.files_scanned} files, {result.threats_found} threats")
        return result
    
    def _get_drives(self) -> List[str]:
        """Get list of available drives"""
        drives = []
        
        if sys.platform == 'win32':
            # Windows drives
            for letter in 'ABCDEFGHIJKLMNOPQRSTUVWXYZ':
                drive = f"{letter}:\\"
                if os.path.exists(drive):
                    drives.append(drive)
        else:
            # Unix-like systems
            drives.append('/')
        
        return drives
