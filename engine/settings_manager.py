"""
SecureGuard Settings Manager
===========================

Handles all user-configurable settings including:
- Real-time protection toggle
- Scan scheduling
- Exclusions list
- Notifications
"""

import json
import os
from pathlib import Path
from typing import Dict, List, Optional
from datetime import datetime


class SettingsManager:
    """Manages all user-configurable settings"""

    def __init__(self, config_file: str = "config/settings.json"):
        self.config_file = config_file
        self.settings = self._load_settings()

    def _load_settings(self) -> Dict:
        """Load settings from file"""
        if os.path.exists(self.config_file):
            try:
                with open(self.config_file, 'r') as f:
                    return json.load(f)
            except:
                return self._default_settings()
        return self._default_settings()

    def _default_settings(self) -> Dict:
        """Default settings"""
        return {
            "realtime_protection": True,
            "auto_update": True,
            "scan_settings": {
                "quick_scan_paths": ["C:\\Users", "C:\\Downloads"],
                "excluded_paths": ["C:\\Windows\\System32"],
                "max_file_size_mb": 500,
                "scan_schedule": {
                    "enabled": False,
                    "scan_type": "quick",
                    "time": "02:00",
                    "days": ["Sunday"]
                }
            },
            "performance": {
                "max_cpu_percent": 5,
                "max_memory_mb": 150,
                "scan_priority": "low"
            },
            "network": {
                "enable_firewall": True,
                "block_suspicious_ips": True,
                "dns_filtering": True
            },
            "ransomware_protection": {
                "enabled": True,
                "file_change_threshold": 50,
                "time_window_seconds": 10
            },
            "notifications": {
                "enabled": True,
                "threat_alerts": True,
                "scan_completed": True,
                "update_available": True,
                "sound_enabled": True
            },
            "exclusions": {
                "paths": [],
                "extensions": [],
                "processes": []
            }
        }

    def _save_settings(self):
        """Save settings to file"""
        os.makedirs(os.path.dirname(self.config_file), exist_ok=True)
        with open(self.config_file, 'w') as f:
            json.dump(self.settings, f, indent=2)

    # ============ Real-Time Protection ============
    def get_realtime_protection(self) -> bool:
        """Get real-time protection status"""
        return self.settings.get("realtime_protection", True)

    def set_realtime_protection(self, enabled: bool):
        """Toggle real-time protection"""
        self.settings["realtime_protection"] = enabled
        self._save_settings()
        return {"success": True, "realtime_protection": enabled}

    # ============ Auto Updates ============
    def get_auto_update(self) -> bool:
        """Get auto-update status"""
        return self.settings.get("auto_update", True)

    def set_auto_update(self, enabled: bool):
        """Toggle auto-update"""
        self.settings["auto_update"] = enabled
        self._save_settings()
        return {"success": True, "auto_update": enabled}

    # ============ Scan Schedule ============
    def get_scan_schedule(self) -> Dict:
        """Get scan schedule settings"""
        return self.settings.get("scan_settings", {}).get("scan_schedule", {})

    def set_scan_schedule(self, enabled: bool, scan_type: str = "quick",
                          time: str = "02:00", days: List[str] = None):
        """Configure scan schedule"""
        if days is None:
            days = ["Sunday"]

        if "scan_settings" not in self.settings:
            self.settings["scan_settings"] = {}

        self.settings["scan_settings"]["scan_schedule"] = {
            "enabled": enabled,
            "scan_type": scan_type,
            "time": time,
            "days": days
        }
        self._save_settings()
        return {"success": True, "scan_schedule": self.get_scan_schedule()}

    # ============ Exclusions ============
    def get_exclusions(self) -> Dict:
        """Get exclusions list"""
        return self.settings.get("exclusions", {"paths": [], "extensions": [], "processes": []})

    def add_exclusion(self, exclusion_type: str, value: str):
        """Add an exclusion (paths, extensions, processes)"""
        exclusions = self.get_exclusions()

        if exclusion_type in ["paths", "extensions", "processes"]:
            if value not in exclusions[exclusion_type]:
                exclusions[exclusion_type].append(value)
                self.settings["exclusions"] = exclusions
                self._save_settings()

        return {"success": True, "exclusions": exclusions}

    def remove_exclusion(self, exclusion_type: str, value: str):
        """Remove an exclusion"""
        exclusions = self.get_exclusions()

        if exclusion_type in ["paths", "extensions", "processes"]:
            if value in exclusions[exclusion_type]:
                exclusions[exclusion_type].remove(value)
                self.settings["exclusions"] = exclusions
                self._save_settings()

        return {"success": True, "exclusions": exclusions}

    # ============ Notifications ============
    def get_notifications(self) -> Dict:
        """Get notification settings"""
        return self.settings.get("notifications", {
            "enabled": True,
            "threat_alerts": True,
            "scan_completed": True,
            "update_available": True,
            "sound_enabled": True
        })

    def set_notifications(self, enabled: bool = None,
                          threat_alerts: bool = None,
                          scan_completed: bool = None,
                          update_available: bool = None,
                          sound_enabled: bool = None):
        """Configure notifications"""
        notifications = self.get_notifications()

        if enabled is not None:
            notifications["enabled"] = enabled
        if threat_alerts is not None:
            notifications["threat_alerts"] = threat_alerts
        if scan_completed is not None:
            notifications["scan_completed"] = scan_completed
        if update_available is not None:
            notifications["update_available"] = update_available
        if sound_enabled is not None:
            notifications["sound_enabled"] = sound_enabled

        self.settings["notifications"] = notifications
        self._save_settings()
        return {"success": True, "notifications": notifications}

    # ============ General Settings ============
    def get_all_settings(self) -> Dict:
        """Get all settings"""
        return self.settings

    def reset_to_defaults(self):
        """Reset all settings to defaults"""
        self.settings = self._default_settings()
        self._save_settings()
        return {"success": True, "message": "Settings reset to defaults"}


# Singleton instance
_settings_manager = None


def get_settings_manager() -> SettingsManager:
    global _settings_manager
    if _settings_manager is None:
        _settings_manager = SettingsManager()
    return _settings_manager
