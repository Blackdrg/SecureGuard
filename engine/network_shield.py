import socket
import threading
from typing import Set, List

class NetworkShield:
    def __init__(self):
        self.running = False
        self.blocked_ips = self._load_blacklist()
        self.suspicious_connections = []
        
    def _load_blacklist(self) -> Set[str]:
        return {
            "192.0.2.1",
            "198.51.100.1",
            "203.0.113.1"
        }
    
    def check_ip(self, ip: str) -> bool:
        return ip in self.blocked_ips
    
    def get_active_connections(self) -> List[dict]:
        import psutil
        connections = []
        for conn in psutil.net_connections(kind='inet'):
            if conn.raddr:
                connections.append({
                    'local': f"{conn.laddr.ip}:{conn.laddr.port}",
                    'remote': f"{conn.raddr.ip}:{conn.raddr.port}",
                    'status': conn.status
                })
        return connections
    
    def start_monitoring(self):
        self.running = True
        threading.Thread(target=self._monitor_loop, daemon=True).start()
    
    def _monitor_loop(self):
        while self.running:
            connections = self.get_active_connections()
            for conn in connections:
                remote_ip = conn['remote'].split(':')[0]
                if self.check_ip(remote_ip):
                    self.suspicious_connections.append(conn)
            threading.Event().wait(3)
    
    def stop(self):
        self.running = False
