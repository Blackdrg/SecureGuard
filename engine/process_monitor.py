import psutil
import threading
import time
from typing import List, Dict, Optional
from datetime import datetime

class ProcessMonitor:
    """Enhanced process monitor with behavior analysis"""
    
    # Known malicious process names
    MALICIOUS_PROCESS_NAMES = [
        'mimikatz', 'procdump', 'pwdump', 'lsass', 'cobaltstrike',
        'metasploit', 'beef', 'nikto', 'nmap', 'netcat', 'nc',
        'psexec', 'wce', 'gsecdump', 'fgdump', 'hashdump',
        'Responder', 'Impacket', 'Kerberoast', 'Mimikatz',
        'powershell', 'cmd', 'regsvr32', 'rundll32', 'mshta',
        'wscript', 'cscript', 'schtasks', 'at', 'sc',
        'net', 'nbtstat', 'netstat', 'nslookup', 'dig'
    ]
    
    # Suspicious process behaviors
    SUSPICIOUS_PATTERNS = {
        'high_cpu': 90.0,
        'high_memory': 60.0,
        'many_threads': 50,
    }
    
    def __init__(self):
        self.running = False
        self.suspicious_processes = []
        self.baseline_processes = set()
        self.process_history = []
        self.monitored_pids = set()
        self.alert_callback = None
        
    def get_all_processes(self) -> List[Dict]:
        """Get all running processes with detailed info"""
        processes = []
        for proc in psutil.process_iter(['pid', 'name', 'username', 'cpu_percent', 
                                         'memory_percent', 'num_threads', 'create_time',
                                         'cmdline', 'exe']):
            try:
                info = proc.info
                info['connections'] = len(proc.connections())
                info['is_system'] = proc.username() and 'SYSTEM' in str(proc.username()).upper()
                processes.append(info)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
        return processes
    
    def scan_processes(self) -> List[Dict]:
        """Scan for suspicious processes"""
        suspicious = []
        processes = self.get_all_processes()
        
        for proc_info in processes:
            reason = self.check_suspicious(proc_info)
            if reason:
                proc_info['suspicion_reason'] = reason
                suspicious.append(proc_info)
                
        self.suspicious_processes = suspicious
        return suspicious
    
    def check_suspicious(self, proc_info: Dict) -> Optional[str]:
        """Check if a process is suspicious"""
        name = proc_info.get('name', '').lower()
        
        # Check against known malicious names
        for malicious in self.MALICIOUS_PROCESS_NAMES:
            if malicious in name:
                return f"Known malicious process: {malicious}"
        
        # Check CPU usage
        if proc_info.get('cpu_percent', 0) > self.SUSPICIOUS_PATTERNS['high_cpu']:
            return f"High CPU usage: {proc_info['cpu_percent']}%"
        
        # Check memory usage
        if proc_info.get('memory_percent', 0) > self.SUSPICIOUS_PATTERNS['high_memory']:
            return f"High memory usage: {proc_info['memory_percent']}%"
        
        # Check thread count
        if proc_info.get('num_threads', 0) > self.SUSPICIOUS_PATTERNS['many_threads']:
            return f"Many threads: {proc_info['num_threads']}"
        
        return None
    
    def detect_suspicious_behavior(self, proc_info: Dict) -> bool:
        """Legacy method for compatibility"""
        return self.check_suspicious(proc_info) is not None
    
    def start_monitoring(self):
        """Start continuous process monitoring"""
        self.running = True
        self.baseline_processes = {p['pid'] for p in self.get_all_processes()}
        threading.Thread(target=self._monitor_loop, daemon=True).start()
        print("[*] Process Monitor started")
    
    def _monitor_loop(self):
        """Background monitoring loop"""
        while self.running:
            try:
                current_procs = self.get_all_processes()
                for proc in current_procs:
                    reason = self.check_suspicious(proc)
                    if reason:
                        proc['detected_at'] = datetime.now().isoformat()
                        proc['suspicion_reason'] = reason
                        self.suspicious_processes.append(proc)
                        if self.alert_callback:
                            self.alert_callback(proc)
                if len(self.suspicious_processes) > 100:
                    self.suspicious_processes = self.suspicious_processes[-100:]
            except Exception as e:
                pass
            time.sleep(3)
    
    def kill_process(self, pid: int) -> bool:
        """Terminate a process"""
        try:
            proc = psutil.Process(pid)
            proc.terminate()
            return True
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return False
    
    def kill_process_force(self, pid: int) -> bool:
        """Force kill a process"""
        try:
            proc = psutil.Process(pid)
            proc.kill()
            return True
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return False
    
    def get_process_info(self, pid: int) -> Optional[Dict]:
        """Get detailed info about a specific process"""
        try:
            proc = psutil.Process(pid)
            return {
                'pid': proc.pid,
                'name': proc.name(),
                'exe': proc.exe(),
                'cmdline': proc.cmdline(),
                'username': proc.username(),
                'create_time': proc.create_time(),
                'cpu_percent': proc.cpu_percent(),
                'memory_info': proc.memory_info()._asdict(),
                'num_threads': proc.num_threads(),
                'connections': [c._asdict() for c in proc.connections()],
            }
        except:
            return None
    
    def set_alert_callback(self, callback):
        """Set callback for suspicious process alerts"""
        self.alert_callback = callback
    
    def stop(self):
        """Stop monitoring"""
        self.running = False
        print("[*] Process Monitor stopped")
