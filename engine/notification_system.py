"""
SecureGuard Notification System
=============================

Handles alerts and notifications for:
- Threat detected
- Scan finished
- Update available
"""

import json
import os
from datetime import datetime
from typing import Dict, List, Optional
from pathlib import Path
import threading


class NotificationSystem:
    """Comprehensive notification system for SecureGuard"""

    def __init__(self):
        self.notifications_dir = Path("logs/notifications")
        self.notifications_dir.mkdir(parents=True, exist_ok=True)
        self.notifications_file = self.notifications_dir / "notifications.json"
        self.notifications = self._load_notifications()
        self.listeners = []

    def _load_notifications(self) -> List[Dict]:
        """Load notifications from file"""
        if self.notifications_file.exists():
            try:
                with open(self.notifications_file, 'r') as f:
                    return json.load(f)
            except:
                return []
        return []

    def _save_notifications(self):
        """Save notifications to file"""
        with open(self.notifications_file, 'w') as f:
            json.dump(self.notifications, f, indent=2, default=str)

    def _notify_listeners(self, notification: Dict):
        """Notify registered listeners"""
        for listener in self.listeners:
            try:
                listener(notification)
            except:
                pass

    def add_listener(self, callback):
        """Add a notification listener"""
        self.listeners.append(callback)

    def remove_listener(self, callback):
        """Remove a notification listener"""
        if callback in self.listeners:
            self.listeners.remove(callback)

    # ============ Threat Alert ============
    def notify_threat_detected(self, threat_name: str, file_path: str,
                               severity: str, action: str) -> Dict:
        """Notify when a threat is detected"""
        notification = {
            "id": len(self.notifications) + 1,
            "type": "threat_detected",
            "timestamp": datetime.now().isoformat(),
            "title": "🚨 Threat Detected",
            "message": f"{threat_name} detected in {file_path}",
            "severity": severity,
            "data": {
                "threat_name": threat_name,
                "file_path": file_path,
                "action": action
            },
            "read": False
        }

        self.notifications.append(notification)
        self._save_notifications()
        self._notify_listeners(notification)

        return notification

    # ============ Scan Completed ============
    def notify_scan_completed(self, scan_type: str, files_scanned: int,
                              threats_found: int, duration: float) -> Dict:
        """Notify when a scan is completed"""
        status = "completed" if threats_found == 0 else "threats_found"

        notification = {
            "id": len(self.notifications) + 1,
            "type": "scan_completed",
            "timestamp": datetime.now().isoformat(),
            "title": "✅ Scan Completed",
            "message": f"{scan_type} scan finished. {files_scanned} files scanned, {threats_found} threats found.",
            "severity": "info" if threats_found == 0 else "warning",
            "data": {
                "scan_type": scan_type,
                "files_scanned": files_scanned,
                "threats_found": threats_found,
                "duration": duration
            },
            "read": False
        }

        self.notifications.append(notification)
        self._save_notifications()
        self._notify_listeners(notification)

        return notification

    # ============ Update Available ============
    def notify_update_available(self, version: str, description: str) -> Dict:
        """Notify when an update is available"""
        notification = {
            "id": len(self.notifications) + 1,
            "type": "update_available",
            "timestamp": datetime.now().isoformat(),
            "title": "🔄 Update Available",
            "message": f"Version {version} is available. {description}",
            "severity": "info",
            "data": {
                "version": version,
                "description": description
            },
            "read": False
        }

        self.notifications.append(notification)
        self._save_notifications()
        self._notify_listeners(notification)

        return notification

    # ============ General Notification ============
    def notify(self, title: str, message: str, severity: str = "info",
               notification_type: str = "general") -> Dict:
        """Send a general notification"""
        notification = {
            "id": len(self.notifications) + 1,
            "type": notification_type,
            "timestamp": datetime.now().isoformat(),
            "title": title,
            "message": message,
            "severity": severity,
            "read": False
        }

        self.notifications.append(notification)
        self._save_notifications()
        self._notify_listeners(notification)

        return notification

    # ============ Query Methods ============
    def get_notifications(self, limit: int = 50, unread_only: bool = False) -> List[Dict]:
        """Get notifications"""
        notifications = self.notifications

        if unread_only:
            notifications = [
                n for n in notifications if not n.get("read", False)]

        return notifications[-limit:]

    def mark_as_read(self, notification_id: int) -> bool:
        """Mark notification as read"""
        for notification in self.notifications:
            if notification["id"] == notification_id:
                notification["read"] = True
                self._save_notifications()
                return True
        return False

    def mark_all_as_read(self):
        """Mark all notifications as read"""
        for notification in self.notifications:
            notification["read"] = True
        self._save_notifications()

    def get_unread_count(self) -> int:
        """Get count of unread notifications"""
        return len([n for n in self.notifications if not n.get("read", False)])

    def clear_notifications(self, older_than_days: int = None):
        """Clear old notifications"""
        if older_than_days is None:
            self.notifications = []
        else:
            from datetime import timedelta
            cutoff = datetime.now() - timedelta(days=older_than_days)
            self.notifications = [
                n for n in self.notifications
                if datetime.fromisoformat(n["timestamp"]) >= cutoff
            ]
        self._save_notifications()

    def export_notifications(self, filepath: str = None) -> str:
        """Export notifications to file"""
        if filepath is None:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filepath = f"logs/notifications_export_{timestamp}.json"

        with open(filepath, 'w') as f:
            json.dump(self.notifications, f, indent=2, default=str)

        return filepath


# Singleton instance
_notification_system = None


def get_notification_system() -> NotificationSystem:
    global _notification_system
    if _notification_system is None:
        _notification_system = NotificationSystem()
    return _notification_system
