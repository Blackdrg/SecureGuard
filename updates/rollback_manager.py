"""
SecureGuard Antivirus - Rollback Manager
=========================================

Manages rollback functionality for system changes and updates.
"""

import os
import sys
import json
import shutil
import tempfile
import hashlib
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Optional, Any


class RollbackManager:
    """Manages rollback of system changes and updates"""
    
    def __init__(self):
        self.backup_dir = Path("config/backups")
        self.backup_dir.mkdir(parents=True, exist_ok=True)
        self.max_backups = 10
        self.current_backup = None
    
    def create_backup(self, name: str, files: List[str] = None) -> bool:
        """Create a backup of specified files or entire system state"""
        print(f"[*] Creating backup: {name}")
        
        try:
            # Create backup folder
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            backup_name = f"{name}_{timestamp}"
            backup_path = self.backup_dir / backup_name
            backup_path.mkdir(parents=True, exist_ok=True)
            
            # Create backup metadata
            metadata = {
                'name': name,
                'timestamp': timestamp,
                'created': datetime.now().isoformat(),
                'files': []
            }
            
            # Backup specified files
            if files:
                for file_path in files:
                    src = Path(file_path)
                    if src.exists():
                        dest = backup_path / src.name
                        shutil.copy2(src, dest)
                        metadata['files'].append(str(src))
                        print(f"    Backed up: {file_path}")
            
            # Save metadata
            meta_file = backup_path / "metadata.json"
            with open(meta_file, 'w') as f:
                json.dump(metadata, f, indent=2)
            
            self.current_backup = backup_path
            print(f"[+] Backup created: {backup_name}")
            return True
            
        except Exception as e:
            print(f"[!] Backup failed: {e}")
            return False
    
    def restore_backup(self, backup_name: str = None) -> bool:
        """Restore from a backup"""
        if backup_name is None:
            backup_name = self._get_latest_backup()
        
        if not backup_name:
            print("[!] No backup found to restore")
            return False
        
        backup_path = self.backup_dir / backup_name
        if not backup_path.exists():
            print(f"[!] Backup not found: {backup_name}")
            return False
        
        print(f"[*] Restoring backup: {backup_name}")
        
        try:
            # Load metadata
            meta_file = backup_path / "metadata.json"
            if meta_file.exists():
                with open(meta_file, 'r') as f:
                    metadata = json.load(f)
                
                # Restore files
                for file_path in metadata.get('files', []):
                    src = backup_path / Path(file_path).name
                    if src.exists():
                        dest = Path(file_path)
                        dest.parent.mkdir(parents=True, exist_ok=True)
                        shutil.copy2(src, dest)
                        print(f"    Restored: {file_path}")
            
            print(f"[+] Backup restored successfully")
            return True
            
        except Exception as e:
            print(f"[!] Restore failed: {e}")
            return False
    
    def list_backups(self) -> List[Dict[str, Any]]:
        """List all available backups"""
        backups = []
        
        try:
            for backup_dir in self.backup_dir.iterdir():
                if backup_dir.is_dir():
                    meta_file = backup_dir / "metadata.json"
                    if meta_file.exists():
                        with open(meta_file, 'r') as f:
                            metadata = json.load(f)
                            backups.append(metadata)
                    else:
                        backups.append({
                            'name': backup_dir.name,
                            'created': 'Unknown'
                        })
        except Exception as e:
            print(f"[!] Error listing backups: {e}")
        
        return sorted(backups, key=lambda x: x.get('created', ''), reverse=True)
    
    def delete_backup(self, backup_name: str) -> bool:
        """Delete a specific backup"""
        backup_path = self.backup_dir / backup_name
        
        if not backup_path.exists():
            print(f"[!] Backup not found: {backup_name}")
            return False
        
        try:
            shutil.rmtree(backup_path)
            print(f"[+] Backup deleted: {backup_name}")
            return True
        except Exception as e:
            print(f"[!] Delete failed: {e}")
            return False
    
    def _get_latest_backup(self) -> Optional[str]:
        """Get the name of the latest backup"""
        backups = self.list_backups()
        if backups:
            return backups[0].get('name')
        return None
    
    def cleanup_old_backups(self):
        """Remove old backups beyond max_backups limit"""
        backups = self.list_backups()
        
        if len(backups) > self.max_backups:
            for backup in backups[self.max_backups:]:
                self.delete_backup(backup.get('name', ''))
    
    def create_system_restore_point(self) -> bool:
        """Create a Windows system restore point (Windows only)"""
        if sys.platform != 'win32':
            print("[!] System restore points are only available on Windows")
            return False
        
        try:
            # This would use Windows System Restore API in production
            # For now, we create a configuration backup
            config_dir = Path("config")
            if config_dir.exists():
                return self.create_backup("system_restore", 
                    [str(f) for f in config_dir.rglob("*.json")])
            return False
        except Exception as e:
            print(f"[!] System restore point creation failed: {e}")
            return False
    
    def verify_backup(self, backup_name: str) -> bool:
        """Verify integrity of a backup"""
        backup_path = self.backup_dir / backup_name
        
        if not backup_path.exists():
            return False
        
        try:
            meta_file = backup_path / "metadata.json"
            if not meta_file.exists():
                return False
            
            with open(meta_file, 'r') as f:
                metadata = json.load(f)
            
            # Check that all files exist
            for file_path in metadata.get('files', []):
                if not (backup_path / Path(file_path).name).exists():
                    return False
            
            return True
        except Exception:
            return False


# Singleton instance
_rollback_manager = None

def get_rollback_manager():
    """Get singleton RollbackManager instance"""
    global _rollback_manager
    if _rollback_manager is None:
        _rollback_manager = RollbackManager()
    return _rollback_manager
