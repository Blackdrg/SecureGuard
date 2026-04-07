import json
import os
from pathlib import Path
from datetime import datetime, timedelta
from typing import List, Dict, Optional
import threading

class ThreatLogger:
    """Comprehensive threat logging and history system"""
    
    def __init__(self):
        self.log_dir = Path("logs")
        self.log_dir.mkdir(exist_ok=True)
        self.threats_file = self.log_dir / "threat_history.json"
        self.threats = self._load_threats()
        self.lock = threading.Lock()
        
    def _load_threats(self) -> List[Dict]:
        """Load threats from file"""
        if self.threats_file.exists():
            try:
                with open(self.threats_file, 'r') as f:
                    return json.load(f)
            except:
                return []
        return []
    
    def _save_threats(self):
        """Save threats to file"""
        with open(self.threats_file, 'w') as f:
            json.dump(self.threats, f, indent=2, default=str)
    
    def log_threat(self, threat_name: str, file_path: str, event_type: str, 
                   action: str, severity: str, detection_method: str = "Unknown"):
        """Log a new threat detection"""
        with self.lock:
            threat_entry = {
                'id': len(self.threats) + 1,
                'timestamp': datetime.now().isoformat(),
                'threat_name': threat_name,
                'file_path': file_path,
                'event_type': event_type,
                'action': action,
                'severity': severity,
                'detection_method': detection_method,
                'status': 'active'
            }
            self.threats.append(threat_entry)
            self._save_threats()
            return threat_entry['id']
    
    def get_all_threats(self) -> List[Dict]:
        """Get all threats"""
        return self.threats
    
    def get_threat_by_id(self, threat_id: int) -> Optional[Dict]:
        """Get threat by ID"""
        for threat in self.threats:
            if threat.get('id') == threat_id:
                return threat
        return None
    
    def filter_threats(self, 
                       severity: Optional[str] = None,
                       date_from: Optional[str] = None,
                       date_to: Optional[str] = None,
                       threat_name: Optional[str] = None,
                       action: Optional[str] = None) -> List[Dict]:
        """Filter threats based on criteria"""
        filtered = self.threats.copy()
        
        if severity:
            filtered = [t for t in filtered if t.get('severity', '').lower() == severity.lower()]
        
        if date_from:
            from_date = datetime.fromisoformat(date_from)
            filtered = [t for t in filtered 
                       if datetime.fromisoformat(t['timestamp']) >= from_date]
        
        if date_to:
            to_date = datetime.fromisoformat(date_to)
            filtered = [t for t in filtered 
                       if datetime.fromisoformat(t['timestamp']) <= to_date]
        
        if threat_name:
            filtered = [t for t in filtered 
                       if threat_name.lower() in t.get('threat_name', '').lower()]
        
        if action:
            filtered = [t for t in filtered 
                       if t.get('action', '').lower() == action.lower()]
        
        return filtered
    
    def search_threats(self, query: str) -> List[Dict]:
        """Search threats by any field"""
        query = query.lower()
        results = []
        for threat in self.threats:
            if (query in threat.get('threat_name', '').lower() or
                query in threat.get('file_path', '').lower() or
                query in threat.get('event_type', '').lower()):
                results.append(threat)
        return results
    
    def get_threats_by_date_range(self, days: int) -> List[Dict]:
        """Get threats from last N days"""
        cutoff = datetime.now() - timedelta(days=days)
        return [t for t in self.threats 
                if datetime.fromisoformat(t['timestamp']) >= cutoff]
    
    def get_threat_statistics(self) -> Dict:
        """Get threat statistics"""
        total = len(self.threats)
        if total == 0:
            return {
                'total_threats': 0,
                'by_severity': {},
                'by_action': {},
                'by_detection_method': {}
            }
        
        by_severity = {}
        by_action = {}
        by_method = {}
        
        for threat in self.threats:
            sev = threat.get('severity', 'Unknown')
            by_severity[sev] = by_severity.get(sev, 0) + 1
            
            act = threat.get('action', 'Unknown')
            by_action[act] = by_action.get(act, 0) + 1
            
            method = threat.get('detection_method', 'Unknown')
            by_method[method] = by_method.get(method, 0) + 1
        
        return {
            'total_threats': total,
            'by_severity': by_severity,
            'by_action': by_action,
            'by_detection_method': by_method
        }
    
    def export_threats(self, format: str = 'json', filepath: Optional[str] = None) -> str:
        """Export threats to file"""
        if not filepath:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filepath = f"logs/threat_export_{timestamp}.{format}"
        
        if format == 'json':
            with open(filepath, 'w') as f:
                json.dump(self.threats, f, indent=2, default=str)
        elif format == 'csv':
            import csv
            if self.threats:
                keys = self.threats[0].keys()
                with open(filepath, 'w', newline='') as f:
                    writer = csv.DictWriter(f, fieldnames=keys)
                    writer.writeheader()
                    writer.writerows(self.threats)
        
        return filepath
    
    def clear_old_threats(self, days: int = 90):
        """Clear threats older than N days"""
        cutoff = datetime.now() - timedelta(days=days)
        original_count = len(self.threats)
        self.threats = [t for t in self.threats 
                       if datetime.fromisoformat(t['timestamp']) >= cutoff]
        self._save_threats()
        return original_count - len(self.threats)


# Singleton instance
_threat_logger = None
def get_threat_logger() -> ThreatLogger:
    global _threat_logger
    if _threat_logger is None:
        _threat_logger = ThreatLogger()
    return _threat_logger
