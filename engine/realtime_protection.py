"""
SecureGuard Antivirus - Real-Time Protection
============================================

Monitors file system in real-time for malicious activity.
"""

import os
import sys
import time
import threading
from pathlib import Path
from datetime import datetime
from typing import Dict, Any, Optional, Callable

# Try to import watchdog for file system monitoring
try:
    from watchdog.observers import Observer
    from watchdog.events import FileSystemEventHandler, FileSystemEvent
    WATCHDOG_AVAILABLE = True
except ImportError:
    WATCHDOG_AVAILABLE = False


class FileProtectionHandler(FileSystemEventHandler):
    """Handler for file system events"""
    
    def __init__(self, detection_engine, quarantine_system, callback: Optional[Callable] = None):
        self.detection_engine = detection_engine
        self.quarantine_system = quarantine_system
        self.callback = callback
        self.protected_extensions = ['.exe', '.dll', '.bat', '.cmd', '.ps1', 
                                     '.vbs', '.js', '.scr', '.com', '.pif']
    
    def on_created(self, event: FileSystemEvent):
        """Called when a file or directory is created"""
        if event.is_directory:
            return
        
        # Check if it's a protected file type
        ext = Path(event.src_path).suffix.lower()
        if ext in self.protected_extensions:
            self._scan_and_protect(event.src_path)
    
    def on_modified(self, event: FileSystemEvent):
        """Called when a file or directory is modified"""
        if event.is_directory:
            return
        
        ext = Path(event.src_path).suffix.lower()
        if ext in self.protected_extensions:
            self._scan_and_protect(event.src_path)
    
    def on_moved(self, event: FileSystemEvent):
        """Called when a file is moved or renamed"""
        if event.is_directory:
            return
        
        # Check destination if it's a move
        if hasattr(event, 'dest_path'):
            dest_ext = Path(event.dest_path).suffix.lower()
            if dest_ext in self.protected_extensions:
                self._scan_and_protect(event.dest_path)
    
    def _scan_and_protect(self, file_path: str):
        """Scan a file and take protective action"""
        try:
            result = self.detection_engine.scan_file(file_path, quarantine=True)
            
            if not result['clean']:
                print(f"[!] Threat detected: {file_path}")
                print(f"    - Threat: {result.get('threat_name')}")
                print(f"    - Type: {result.get('threat_type')}")
                
                if self.callback:
                    self.callback(result)
        except Exception as e:
            pass  # Don't log every error for performance


class RealTimeProtection:
    """Real-time file system protection"""
    
    def __init__(self, detection_engine, quarantine_system):
        self.detection_engine = detection_engine
        self.quarantine_system = quarantine_system
        self.running = False
        self.observer = None
        self.protected_paths = []
        self.callback = None
        
        # File system handler
        self.handler = None
        
        print("[*] Real-Time Protection initialized")
        print(f"    - Watchdog available: {WATCHDOG_AVAILABLE}")
    
    def set_callback(self, callback: Callable):
        """Set callback for threat detection"""
        self.callback = callback
    
    def add_protected_path(self, path: str):
        """Add a path to protect"""
        if path not in self.protected_paths:
            self.protected_paths.append(path)
            if self.running and self.observer:
                self.observer.schedule(self.handler, path, recursive=True)
    
    def remove_protected_path(self, path: str):
        """Remove a path from protection"""
        if path in self.protected_paths:
            self.protected_paths.remove(path)
    
    def start(self):
        """Start real-time protection"""
        if self.running:
            return
        
        if not WATCHDOG_AVAILABLE:
            print("[!] Watchdog not available - using fallback polling")
            self._start_polling()
            return
        
        self.handler = FileProtectionHandler(
            self.detection_engine, 
            self.quarantine_system,
            self.callback
        )
        
        self.observer = Observer()
        
        # Add default protected paths
        default_paths = [
            os.path.expanduser("~/Downloads"),
            os.path.expanduser("~/Documents"),
            "C:\\Windows\\System32",
            "C:\\Program Files",
        ]
        
        for path in default_paths:
            if os.path.exists(path):
                self.observer.schedule(self.handler, path, recursive=True)
                self.protected_paths.append(path)
        
        self.observer.start()
        self.running = True
        
        print(f"[+] Real-Time Protection started")
        print(f"    - Protecting {len(self.protected_paths)} paths")
    
    def _start_polling(self):
        """Start fallback polling-based protection"""
        self.running = True
        self.poll_thread = threading.Thread(target=self._poll_loop, daemon=True)
        self.poll_thread.start()
        print("[+] Real-Time Protection (polling mode) started")
    
    def _poll_loop(self):
        """Fallback polling loop"""
        while self.running:
            try:
                # Check recently created files
                for path in self.protected_paths:
                    if os.path.exists(path):
                        try:
                            recent_files = Path(path).rglob('*.exe')
                            for f in recent_files:
                                if self.detection_engine:
                                    self.detection_engine.scan_file(str(f))
                        except:
                            pass
            except:
                pass
            
            time.sleep(5)  # Poll every 5 seconds
    
    def stop(self):
        """Stop real-time protection"""
        self.running = False
        
        if self.observer:
            self.observer.stop()
            self.observer.join(timeout=5)
            self.observer = None
        
        print("[-] Real-Time Protection stopped")
    
    def get_status(self) -> Dict[str, Any]:
        """Get protection status"""
        return {
            'running': self.running,
            'protected_paths': self.protected_paths,
            'watchdog_available': WATCHDOG_AVAILABLE
        }
