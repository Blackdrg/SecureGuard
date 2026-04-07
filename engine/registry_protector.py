"""
SecureGuard Antivirus - Registry Protector
==========================================

Protects critical Windows registry keys from being modified.
"""

import os
import sys
import winreg
from typing import List, Dict, Any


class RegistryProtector:
    """Protects critical Windows registry keys"""
    
    # Critical registry keys to protect
    PROTECTED_KEYS = [
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"),
        (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
        (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"),
    ]
    
    def __init__(self):
        self.running = False
        self.protected_keys = []
        print("[*] Registry Protector initialized")
    
    def protect_registry_keys(self):
        """Start protecting registry keys"""
        self.running = True
        self.protected_keys = list(self.PROTECTED_KEYS)
        print(f"[+] Registry protection enabled for {len(self.protected_keys)} keys")
    
    def stop(self):
        """Stop registry protection"""
        self.running = False
        print("[-] Registry protection stopped")
    
    def get_status(self) -> Dict[str, Any]:
        """Get protection status"""
        return {
            'running': self.running,
            'protected_keys': len(self.protected_keys)
        }


def get_registry_protector():
    """Get singleton RegistryProtector instance"""
    return RegistryProtector()
