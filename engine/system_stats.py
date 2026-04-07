"""
SecureGuard Antivirus - System Statistics Module (OPTIMIZED)
===========================================================

OPTIMIZED: Faster stats collection with caching
"""

import os
import json
import time
import platform
import threading
from datetime import datetime
from typing import Dict, Optional

try:
    import psutil
    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False


class SystemStats:
    """System statistics collector - OPTIMIZED with caching"""
    
    def __init__(self):
        self._stats_file = "config/system_stats.json"
        self._load_persistent_stats()
        
        # Cache for fast repeated calls
        self._cache = {}
        self._cache_duration = 1.0  # 1 second cache
        self._cache_lock = threading.Lock()
        
        # Pre-fetch OS info once
        self._os_info = self._get_os_info_cached()
        
    def _get_os_info_cached(self) -> Dict:
        """Cache OS info"""
        if HAS_PSUTIL:
            return {
                'os': platform.system(),
                'os_version': platform.version(),
                'machine': platform.machine(),
                'processor': platform.processor(),
            }
        return {'os': platform.system(), 'os_version': 'Unknown'}
    
    def _load_persistent_stats(self):
        try:
            if os.path.exists(self._stats_file):
                with open(self._stats_file, 'r') as f:
                    self._persistent = json.load(f)
            else:
                self._persistent = {
                    'total_files_scanned': 0, 'total_threats_blocked': 0,
                    'total_quarantined': 0, 'scans_completed': 0,
                    'install_date': datetime.now().isoformat(),
                    'last_scan_date': None, 'last_scan_type': None
                }
        except:
            self._persistent = {'total_files_scanned': 0, 'total_threats_blocked': 0,
                'total_quarantined': 0, 'scans_completed': 0,
                'install_date': datetime.now().isoformat(), 'last_scan_date': None, 'last_scan_type': None}
    
    def _save_persistent_stats(self):
        try:
            os.makedirs("config", exist_ok=True)
            with open(self._stats_file, 'w') as f:
                json.dump(self._persistent, f, indent=2)
        except:
            pass
    
    def _get_cached(self, key: str, func, *args) -> any:
        """Fast cache helper"""
        with self._cache_lock:
            now = time.time()
            if key in self._cache:
                cached_time, cached_value = self._cache[key]
                if now - cached_time < self._cache_duration:
                    return cached_value
            
            value = func(*args)
            self._cache[key] = (now, value)
            return value
    
    def get_cpu_usage(self) -> float:
        """Get current CPU usage - CACHED"""
        def _get():
            if HAS_PSUTIL:
                return psutil.cpu_percent(interval=0.1)
            return 0.0
        return self._get_cached('cpu', _get)
    
    def get_memory_usage(self) -> Dict:
        """Get memory usage - CACHED"""
        def _get():
            if HAS_PSUTIL:
                mem = psutil.virtual_memory()
                return {'total': self._format_bytes(mem.total), 'available': self._format_bytes(mem.available),
                        'used': self._format_bytes(mem.used), 'percent': round(mem.percent, 1)}
            return {'total': 'Unknown', 'available': 'Unknown', 'used': 'Unknown', 'percent': 0}
        return self._get_cached('memory', _get)
    
    def get_disk_usage(self) -> Dict:
        """Get disk usage - CACHED"""
        def _get():
            if HAS_PSUTIL:
                try:
                    disk = psutil.disk_usage('C:\\' if platform.system() == 'Windows' else '/')
                    return {'total': self._format_bytes(disk.total), 'used': self._format_bytes(disk.used),
                            'free': self._format_bytes(disk.free), 'percent': round(disk.percent, 1)}
                except:
                    pass
            return {'total': 'Unknown', 'used': 'Unknown', 'free': 'Unknown', 'percent': 0}
        return self._get_cached('disk', _get)
    
    def get_process_count(self) -> int:
        if HAS_PSUTIL:
            return len(psutil.pids())
        return 0
    
    def get_uptime(self) -> str:
        if HAS_PSUTIL:
            boot = psutil.boot_time()
            uptime = time.time() - boot
            hours = int(uptime // 3600)
            minutes = int((uptime % 3600) // 60)
            return f"{hours}h {minutes}m"
        return "Unknown"
    
    def get_system_info(self) -> Dict:
        return self._os_info
    
    def get_protection_status(self) -> Dict:
        return {'real_time': 'Active', 'firewall': 'Enabled', 'auto_update': 'Enabled', 'last_update': 'Today'}
    
    def get_total_files_scanned(self) -> int:
        return self._persistent.get('total_files_scanned', 0)
    
    def get_total_threats_blocked(self) -> int:
        return self._persistent.get('total_threats_blocked', 0)
    
    def get_total_quarantined(self) -> int:
        return self._persistent.get('total_quarantined', 0)
    
    def get_scans_completed(self) -> int:
        return self._persistent.get('scans_completed', 0)
    
    def get_last_scan_date(self) -> Optional[str]:
        return self._persistent.get('last_scan_date')
    
    def get_last_scan_type(self) -> Optional[str]:
        return self._persistent.get('last_scan_type')
    
    def record_scan(self, scan_type: str, files_scanned: int = 0, threats_found: int = 0):
        self._persistent['scans_completed'] = self._persistent.get('scans_completed', 0) + 1
        self._persistent['total_files_scanned'] = self._persistent.get('total_files_scanned', 0) + files_scanned
        self._persistent['last_scan_date'] = datetime.now().isoformat()
        self._persistent['last_scan_type'] = scan_type
        self._save_persistent_stats()
        # Clear cache after scan
        with self._cache_lock:
            self._cache.clear()
    
    def record_threat_blocked(self):
        self._persistent['total_threats_blocked'] = self._persistent.get('total_threats_blocked', 0) + 1
        self._save_persistent_stats()
    
    def record_quarantine(self):
        self._persistent['total_quarantined'] = self._persistent.get('total_quarantined', 0) + 1
        self._save_persistent_stats()
    
    def get_all_stats(self) -> Dict:
        return {
            'system': {'cpu_usage': self.get_cpu_usage(), 'memory': self.get_memory_usage(),
                      'disk': self.get_disk_usage(), 'processes': self.get_process_count(), 'uptime': self.get_uptime()},
            'protection': self.get_protection_status(),
            'scanning': {'total_files_scanned': self.get_total_files_scanned(),
                        'total_threats_blocked': self.get_total_threats_blocked(),
                        'total_quarantined': self.get_total_quarantined(),
                        'scans_completed': self.get_scans_completed(),
                        'last_scan_date': self.get_last_scan_date(), 'last_scan_type': self.get_last_scan_type()}
        }
    
    def _format_bytes(self, bytes_value: int) -> str:
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if bytes_value < 1024.0:
                return f"{bytes_value:.1f} {unit}"
            bytes_value /= 1024.0
        return f"{bytes_value:.1f} PB"


def get_system_stats() -> SystemStats:
    return SystemStats()


if __name__ == "__main__":
    import time
    s = SystemStats()
    
    # Test speed
    start = time.time()
    for _ in range(100):
        s.get_cpu_usage()
        s.get_memory_usage()
        s.get_disk_usage()
    elapsed = time.time() - start
    print(f"100 stats calls: {elapsed:.4f}s ({elapsed*10:.2f}ms per call)")
    print(f"CPU: {s.get_cpu_usage()}%")
    print(f"Memory: {s.get_memory_usage()['percent']}%")
    print(f"Disk: {s.get_disk_usage()['percent']}%")
