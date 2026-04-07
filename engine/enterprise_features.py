import os
import threading
import time
import json
from datetime import datetime
from typing import List, Dict, Optional
from pathlib import Path
import winreg

class DeviceControl:
    """Enterprise device control - block USB drives and external devices"""
    
    def __init__(self):
        self.blocked_devices = set()
        self.allowed_devices = set()
        self.block_usb = True
        self.block_external = True
        self.monitoring = False
        
    def start_monitoring(self):
        """Start device monitoring"""
        self.monitoring = True
        threading.Thread(target=self._monitor_devices, daemon=True).start()
        
    def stop_monitoring(self):
        """Stop device monitoring"""
        self.monitoring = False
        
    def _monitor_devices(self):
        """Monitor for new devices"""
        import psutil
        previous = set(p.device for p in psutil.disk_partitions() if 'removable' in p.opts)
        
        while self.monitoring:
            time.sleep(2)
            current = set(p.device for p in psutil.disk_partitions() if 'removable' in p.opts)
            new = current - previous
            
            for device in new:
                if self.should_block(device):
                    self._block_device(device)
            
            previous = current
    
    def should_block(self, device: str) -> bool:
        """Check if device should be blocked"""
        if self.block_usb and 'usb' in device.lower():
            return True
        if self.block_external and 'external' in device.lower():
            return True
        return False
    
    def _block_device(self, device: str):
        """Block a device"""
        self.blocked_devices.add(device)
        print(f"[DEVICE CONTROL] Blocked: {device}")
    
    def block_device(self, device_id: str):
        """Manually block a device"""
        self.blocked_devices.add(device_id)
    
    def allow_device(self, device_id: str):
        """Allow a previously blocked device"""
        if device_id in self.blocked_devices:
            self.blocked_devices.remove(device_id)
        self.allowed_devices.add(device_id)
    
    def get_blocked_devices(self) -> List[str]:
        """Get list of blocked devices"""
        return list(self.blocked_devices)
    
    def get_status(self) -> Dict:
        """Get device control status"""
        return {
            'usb_blocked': self.block_usb,
            'external_blocked': self.block_external,
            'blocked_count': len(self.blocked_devices),
            'allowed_count': len(self.allowed_devices),
            'monitoring': self.monitoring
        }


class ApplicationControl:
    """Enterprise application control - allow only trusted programs"""
    
    def __init__(self):
        self.trusted_apps = set()
        self.blocked_apps = set()
        self.monitoring = False
        self.default_action = 'allow'  # allow or block
        
    def start_monitoring(self):
        """Start application monitoring"""
        self.monitoring = True
        threading.Thread(target=self._monitor_processes, daemon=True).start()
        
    def stop_monitoring(self):
        """Stop application monitoring"""
        self.monitoring = False
    
    def _monitor_processes(self):
        """Monitor running processes"""
        import psutil
        
        while self.monitoring:
            time.sleep(5)
            for proc in psutil.process_iter(['name', 'exe']):
                try:
                    app_name = proc.info['name']
                    if not self.is_allowed(app_name):
                        self._terminate_process(proc)
                except:
                    pass
    
    def is_allowed(self, app_name: str) -> bool:
        """Check if application is allowed"""
        if app_name in self.blocked_apps:
            return False
        if app_name in self.trusted_apps:
            return True
        return self.default_action == 'allow'
    
    def _terminate_process(self, proc):
        """Terminate a process"""
        try:
            proc.kill()
            print(f"[APP CONTROL] Terminated: {proc.info['name']}")
        except:
            pass
    
    def add_trusted(self, app_name: str):
        """Add application to trusted list"""
        self.trusted_apps.add(app_name)
        if app_name in self.blocked_apps:
            self.blocked_apps.remove(app_name)
    
    def block_application(self, app_name: str):
        """Block an application"""
        self.blocked_apps.add(app_name)
        if app_name in self.trusted_apps:
            self.trusted_apps.remove(app_name)
    
    def get_trusted_apps(self) -> List[str]:
        """Get trusted applications"""
        return list(self.trusted_apps)
    
    def get_blocked_apps(self) -> List[str]:
        """Get blocked applications"""
        return list(self.blocked_apps)
    
    def get_status(self) -> Dict:
        """Get application control status"""
        return {
            'trusted_count': len(self.trusted_apps),
            'blocked_count': len(self.blocked_apps),
            'default_action': self.default_action,
            'monitoring': self.monitoring
        }


class FirewallManager:
    """Advanced firewall manager with inbound/outbound rules"""
    
    def __init__(self):
        self.rules = []
        self.enabled = True
        
    def add_rule(self, name: str, direction: str, action: str, 
                 port: int = None, ip: str = None, protocol: str = 'TCP'):
        """Add firewall rule"""
        rule = {
            'id': len(self.rules) + 1,
            'name': name,
            'direction': direction,  # inbound or outbound
            'action': action,  # allow or block
            'port': port,
            'ip': ip,
            'protocol': protocol,
            'enabled': True,
            'created': datetime.now().isoformat()
        }
        self.rules.append(rule)
        return rule['id']
    
    def block_port(self, port: int, direction: str = 'inbound'):
        """Block a port"""
        return self.add_rule(
            name=f'Block Port {port}',
            direction=direction,
            action='block',
            port=port
        )
    
    def allow_port(self, port: int, direction: str = 'inbound'):
        """Allow a port"""
        return self.add_rule(
            name=f'Allow Port {port}',
            direction=direction,
            action='allow',
            port=port
        )
    
    def block_ip(self, ip: str, direction: str = 'inbound'):
        """Block an IP address"""
        return self.add_rule(
            name=f'Block IP {ip}',
            direction=direction,
            action='block',
            ip=ip
        )
    
    def block_domain(self, domain: str):
        """Block a domain"""
        return self.add_rule(
            name=f'Block Domain {domain}',
            direction='outbound',
            action='block',
            ip=domain
        )
    
    def remove_rule(self, rule_id: int) -> bool:
        """Remove a firewall rule"""
        for rule in self.rules:
            if rule['id'] == rule_id:
                self.rules.remove(rule)
                return True
        return False
    
    def get_rules(self, direction: str = None) -> List[Dict]:
        """Get firewall rules"""
        if direction:
            return [r for r in self.rules if r['direction'] == direction]
        return self.rules
    
    def get_status(self) -> Dict:
        """Get firewall status"""
        inbound = len([r for r in self.rules if r['direction'] == 'inbound'])
        outbound = len([r for r in self.rules if r['direction'] == 'outbound'])
        
        return {
            'enabled': self.enabled,
            'total_rules': len(self.rules),
            'inbound_rules': inbound,
            'outbound_rules': outbound
        }


class RemoteDashboard:
    """Enterprise remote threat dashboard for multiple devices"""
    
    def __init__(self):
        self.devices = {}
        self.alerts = []
        
    def register_device(self, device_id: str, device_name: str, 
                       ip_address: str = None):
        """Register a device for monitoring"""
        self.devices[device_id] = {
            'id': device_id,
            'name': device_name,
            'ip': ip_address,
            'status': 'online',
            'last_seen': datetime.now().isoformat(),
            'threats': [],
            'security_score': 100
        }
    
    def update_device_status(self, device_id: str, status: str,
                           threats: List[Dict] = None, score: int = None):
        """Update device status"""
        if device_id in self.devices:
            self.devices[device_id]['status'] = status
            self.devices[device_id]['last_seen'] = datetime.now().isoformat()
            
            if threats is not None:
                self.devices[device_id]['threats'] = threats
            
            if score is not None:
                self.devices[device_id]['security_score'] = score
    
    def get_device(self, device_id: str) -> Optional[Dict]:
        """Get device info"""
        return self.devices.get(device_id)
    
    def get_all_devices(self) -> List[Dict]:
        """Get all registered devices"""
        return list(self.devices.values())
    
    def add_alert(self, device_id: str, alert_type: str, 
                 severity: str, message: str):
        """Add an alert"""
        alert = {
            'id': len(self.alerts) + 1,
            'device_id': device_id,
            'type': alert_type,
            'severity': severity,
            'message': message,
            'timestamp': datetime.now().isoformat()
        }
        self.alerts.append(alert)
        
        # Keep only last 100 alerts
        if len(self.alerts) > 100:
            self.alerts = self.alerts[-100:]
        
        return alert
    
    def get_alerts(self, device_id: str = None, 
                  severity: str = None, limit: int = 50) -> List[Dict]:
        """Get alerts"""
        alerts = self.alerts
        
        if device_id:
            alerts = [a for a in alerts if a['device_id'] == device_id]
        
        if severity:
            alerts = [a for a in alerts if a['severity'] == severity]
        
        return alerts[-limit:]
    
    def get_dashboard_summary(self) -> Dict:
        """Get dashboard summary"""
        total = len(self.devices)
        online = len([d for d in self.devices.values() if d['status'] == 'online'])
        offline = total - online
        
        avg_score = 0
        if total > 0:
            avg_score = sum(d['security_score'] for d in self.devices.values()) / total
        
        critical_alerts = len([a for a in self.alerts if a['severity'] == 'Critical'])
        
        return {
            'total_devices': total,
            'online_devices': online,
            'offline_devices': offline,
            'average_security_score': int(avg_score),
            'critical_alerts': critical_alerts,
            'total_alerts': len(self.alerts)
        }
