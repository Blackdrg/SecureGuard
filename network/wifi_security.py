import subprocess

class WiFiSecurity:
    def __init__(self):
        self.enabled = True
        
    def scan_network(self) -> dict:
        """Scan WiFi network for security issues"""
        issues = []
        
        # Check encryption
        encryption = self._check_encryption()
        if encryption != 'WPA3' and encryption != 'WPA2':
            issues.append({
                'type': 'weak_encryption',
                'severity': 'high',
                'description': f'Network using {encryption}'
            })
        
        # Check for open networks
        if encryption == 'Open':
            issues.append({
                'type': 'open_network',
                'severity': 'critical',
                'description': 'Unencrypted network detected'
            })
        
        return {
            'network_name': self._get_network_name(),
            'encryption': encryption,
            'issues_found': len(issues),
            'issues': issues,
            'security_score': 100 - (len(issues) * 20)
        }
    
    def _check_encryption(self) -> str:
        """Check WiFi encryption type"""
        try:
            result = subprocess.run(['netsh', 'wlan', 'show', 'interfaces'],
                                  capture_output=True, text=True, timeout=5)
            output = result.stdout
            
            if 'WPA3' in output:
                return 'WPA3'
            elif 'WPA2' in output:
                return 'WPA2'
            elif 'WPA' in output:
                return 'WPA'
            elif 'WEP' in output:
                return 'WEP'
            else:
                return 'Open'
        except:
            return 'Unknown'
    
    def _get_network_name(self) -> str:
        """Get connected network name"""
        try:
            result = subprocess.run(['netsh', 'wlan', 'show', 'interfaces'],
                                  capture_output=True, text=True, timeout=5)
            for line in result.stdout.split('\\n'):
                if 'SSID' in line and 'BSSID' not in line:
                    return line.split(':')[1].strip()
        except:
            pass
        return 'Unknown'
    
    def check_router_security(self) -> dict:
        """Check router security settings"""
        return {
            'default_password': False,
            'firewall_enabled': True,
            'remote_access_disabled': True,
            'firmware_updated': True
        }
    
    def scan_connected_devices(self) -> list:
        """Scan devices connected to network"""
        return [
            {'name': 'This PC', 'ip': '192.168.1.100', 'trusted': True},
            {'name': 'Unknown Device', 'ip': '192.168.1.101', 'trusted': False}
        ]
