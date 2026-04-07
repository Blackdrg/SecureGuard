"""
SecureGuard Antivirus - Update Manager
=========================================

Manages automatic updates for virus definitions and software updates.
"""

import os
import sys
import json
import time
import hashlib
import threading
import requests
from datetime import datetime, timedelta
from pathlib import Path


class UpdateManager:
    """Manages virus definition updates and software updates"""
    
    # Update server URLs (these would be real URLs in production)
    DEFINITIONS_URL = "https://definitions.secureguard.example.com"
    SOFTWARE_URL = "https://updates.secureguard.example.com"
    
    def __init__(self):
        self.update_interval = 3600  # Check for updates every hour
        self.running = False
        self.update_thread = None
        self.last_update = None
        self.current_version = "1.0.0"
        self.definitions_version = "2024.01.01"
        self.update_callback = None
        
        # Local definitions path
        self.definitions_dir = Path("config/definitions")
        self.definitions_dir.mkdir(parents=True, exist_ok=True)
        
        # Load last update info
        self.load_update_info()
    
    def load_update_info(self):
        """Load update information from disk"""
        info_file = Path("config/update_info.json")
        if info_file.exists():
            try:
                with open(info_file, 'r') as f:
                    info = json.load(f)
                    self.last_update = info.get('last_update')
                    self.definitions_version = info.get('definitions_version', '2024.01.01')
            except Exception:
                pass
    
    def save_update_info(self):
        """Save update information to disk"""
        info_file = Path("config/update_info.json")
        info_file.parent.mkdir(parents=True, exist_ok=True)
        
        info = {
            'last_update': datetime.now().isoformat(),
            'definitions_version': self.definitions_version,
            'software_version': self.current_version
        }
        
        with open(info_file, 'w') as f:
            json.dump(info, f, indent=2)
    
    def check_updates(self):
        """Check for available updates"""
        print("[*] Checking for updates...")
        
        try:
            # In production, this would make actual HTTP requests
            # For now, we simulate the update check
            
            # Check definitions update
            definitions_available = self._check_definitions_update()
            
            # Check software update
            software_available = self._check_software_update()
            
            result = {
                'definitions_available': definitions_available,
                'software_available': software_available,
                'definitions_version': self.definitions_version,
                'software_version': self.current_version
            }
            
            print(f"[+] Update check complete: definitions={definitions_available}, software={software_available}")
            return result
            
        except Exception as e:
            print(f"[!] Update check failed: {e}")
            return {'error': str(e)}
    
    def _check_definitions_update(self):
        """Check if new definitions are available"""
        # Simulate checking definitions version
        # In production: requests.get(f"{self.DEFINITIONS_URL}/version")
        return False  # No update available for now
    
    def _check_software_update(self):
        """Check if software update is available"""
        # Simulate checking software version
        # In production: requests.get(f"{self.SOFTWARE_URL}/version")
        return False  # No update available for now
    
    def download_definitions(self):
        """Download latest virus definitions"""
        print("[*] Downloading virus definitions...")
        
        try:
            # In production, this would download actual definitions
            # For simulation, we create a mock definitions file
            
            definitions = {
                'version': datetime.now().strftime("%Y.%m.%d"),
                'last_updated': datetime.now().isoformat(),
                'signatures': self._get_default_signatures(),
                'count': len(self._get_default_signatures())
            }
            
            # Save definitions
            def_file = self.definitions_dir / f"definitions_{definitions['version']}.json"
            with open(def_file, 'w') as f:
                json.dump(definitions, f, indent=2)
            
            self.definitions_version = definitions['version']
            self.save_update_info()
            
            print(f"[+] Definitions updated to version {self.definitions_version}")
            return True
            
        except Exception as e:
            print(f"[!] Failed to download definitions: {e}")
            return False
    
    def _get_default_signatures(self):
        """Get default virus signatures"""
        return {
            # Common malware signatures (hashes)
            "eicar": "44d88612fea8a8f36de82e1278abb02f",
            "test_malware_1": "5d41402abc4b2a76b9719d911017c592",
            "test_malware_2": "098f6bcd4621d373cade4e832627b4f6",
        }
    
    def update_definitions(self):
        """Update virus definitions"""
        if self.download_definitions():
            print("[+] Virus definitions updated successfully")
            return True
        return False
    
    def start_auto_update(self):
        """Start automatic update background thread"""
        if self.running:
            return
        
        self.running = True
        self.update_thread = threading.Thread(target=self._update_loop, daemon=True)
        self.update_thread.start()
        print("[+] Auto-update service started")
    
    def stop_auto_update(self):
        """Stop automatic update"""
        self.running = False
        if self.update_thread:
            self.update_thread.join(timeout=5)
        print("[-] Auto-update service stopped")
    
    def _update_loop(self):
        """Background update loop"""
        while self.running:
            try:
                self.check_updates()
                # Check if definitions need update
                if self._check_definitions_update():
                    self.update_definitions()
            except Exception as e:
                print(f"[!] Auto-update error: {e}")
            
            # Wait for next update check
            for _ in range(self.update_interval):
                if not self.running:
                    break
                time.sleep(1)
    
    def get_definition_count(self):
        """Get number of virus definitions"""
        return len(self._get_default_signatures())
    
    def get_version_info(self):
        """Get version information"""
        return {
            'software_version': self.current_version,
            'definitions_version': self.definitions_version,
            'last_update': self.last_update,
            'update_available': self._check_definitions_update() or self._check_software_update()
        }
    
    def rollback_definitions(self):
        """Rollback to previous definitions"""
        # List available definition files
        def_files = sorted(self.definitions_dir.glob("definitions_*.json"))
        
        if len(def_files) < 2:
            print("[!] No previous definitions to rollback to")
            return False
        
        # Load previous definitions
        prev_file = def_files[-2]  # Second to last is previous
        try:
            with open(prev_file, 'r') as f:
                prev_defs = json.load(f)
            
            self.definitions_version = prev_defs.get('version', 'unknown')
            self.save_update_info()
            print(f"[+] Rolled back to definitions version {self.definitions_version}")
            return True
        except Exception as e:
            print(f"[!] Rollback failed: {e}")
            return False


# Singleton instance
_update_manager = None

def get_update_manager():
    """Get singleton UpdateManager instance"""
    global _update_manager
    if _update_manager is None:
        _update_manager = UpdateManager()
    return _update_manager
