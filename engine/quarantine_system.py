import os
import shutil
import json
from datetime import datetime
from pathlib import Path
import base64

class QuarantineSystem:
    """Enhanced quarantine system for isolating threats"""
    
    def __init__(self):
        self.quarantine_path = Path('quarantine')
        self.quarantine_path.mkdir(exist_ok=True)
        self.index_file = self.quarantine_path / 'index.json'
        self.index = self._load_index()
        
    def _load_index(self):
        if self.index_file.exists():
            try:
                with open(self.index_file, 'r') as f:
                    return json.load(f)
            except:
                return {}
        return {}
        
    def _save_index(self):
        with open(self.index_file, 'w') as f:
            json.dump(self.index, f, indent=2, default=str)
    
    def quarantine(self, filepath, threat_name="Unknown", severity="Medium"):
        """Quarantine a file"""
        threat_info = {
            'threat_name': threat_name,
            'method': 'signature',
            'severity': severity
        }
        return self.isolate(filepath, threat_info)
    
    def isolate(self, filepath, threat_info):
        """Isolate a malicious file to quarantine"""
        try:
            if not os.path.exists(filepath):
                return False
                
            file_id = datetime.now().strftime('%Y%m%d_%H%M%S_%f')
            quarantine_file = self.quarantine_path / f'{file_id}.quar'
            
            original_name = os.path.basename(filepath)
            
            with open(filepath, 'rb') as f:
                data = f.read()
            encrypted = self._encrypt(data)
            
            with open(quarantine_file, 'wb') as f:
                f.write(encrypted)
                
            self.index[file_id] = {
                'original_name': original_name,
                'original_path': str(filepath),
                'quarantine_path': str(quarantine_file),
                'threat_name': threat_info.get('threat_name', 'Unknown'),
                'detection_method': threat_info.get('method', 'Unknown'),
                'severity': threat_info.get('severity', 'Medium'),
                'timestamp': datetime.now().isoformat(),
                'size': len(data)
            }
            self._save_index()
            
            try:
                os.remove(filepath)
            except:
                pass
                
            return True
        except Exception as e:
            print(f"[!] Quarantine error: {e}")
            return False
            
    def restore(self, file_id):
        """Restore a file from quarantine"""
        if file_id not in self.index:
            return False
            
        try:
            info = self.index[file_id]
            quarantine_file = Path(info['quarantine_path'])
            
            if not quarantine_file.exists():
                return False
            
            with open(quarantine_file, 'rb') as f:
                encrypted = f.read()
            data = self._decrypt(encrypted)
            
            original_path = Path(info['original_path'])
            original_path.parent.mkdir(parents=True, exist_ok=True)
            
            with open(original_path, 'wb') as f:
                f.write(data)
                
            try:
                quarantine_file.unlink()
            except:
                pass
                
            del self.index[file_id]
            self._save_index()
            
            return True
        except Exception as e:
            print(f"[!] Restore error: {e}")
            return False
            
    def delete_permanent(self, file_id):
        """Permanently delete a quarantined file"""
        if file_id not in self.index:
            return False
            
        try:
            info = self.index[file_id]
            quarantine_file = Path(info['quarantine_path'])
            
            if quarantine_file.exists():
                try:
                    size = quarantine_file.stat().st_size
                    with open(quarantine_file, 'wb') as f:
                        f.write(os.urandom(size))
                    quarantine_file.unlink()
                except:
                    pass
                
            del self.index[file_id]
            self._save_index()
            return True
        except Exception as e:
            print(f"[!] Delete error: {e}")
            return False
    
    def delete(self, file_id):
        """Alias for delete_permanent"""
        return self.delete_permanent(file_id)
            
    def list_quarantined(self):
        """List all quarantined files"""
        return self.index
    
    def get_quarantined_count(self):
        """Get count of quarantined files"""
        return len(self.index)
    
    def clear_all(self):
        """Clear all quarantined files"""
        for file_id in list(self.index.keys()):
            self.delete_permanent(file_id)
        return True
        
    def _encrypt(self, data):
        key = b'SecureGuardKey123'
        return bytes([b ^ key[i % len(key)] for i, b in enumerate(data)])
        
    def _decrypt(self, data):
        return self._encrypt(data)
