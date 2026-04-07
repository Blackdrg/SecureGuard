"""
WebSocket Router for Real-time Updates
Provides WebSocket endpoints for live threat notifications, scan updates, and device telemetry
"""

from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from typing import List, Dict, Any
import json
from datetime import datetime

router = APIRouter()


class ConnectionManager:
    """Manages WebSocket connections for real-time updates"""
    
    def __init__(self):
        self.active_connections: List[WebSocket] = []
        self.admin_connections: List[WebSocket] = []
    
    async def connect(self, websocket: WebSocket, is_admin: bool = False):
        await websocket.accept()
        if is_admin:
            self.admin_connections.append(websocket)
        else:
            self.active_connections.append(websocket)
    
    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)
        if websocket in self.admin_connections:
            self.admin_connections.remove(websocket)
    
    async def send_personal_message(self, message: Dict[str, Any], websocket: WebSocket):
        await websocket.send_json(message)
    
    async def broadcast(self, message: Dict[str, Any]):
        """Broadcast to all regular connections"""
        for connection in self.active_connections:
            try:
                await connection.send_json(message)
            except Exception:
                pass
    
    async def broadcast_to_admins(self, message: Dict[str, Any]):
        """Broadcast to admin connections only"""
        for connection in self.admin_connections:
            try:
                await connection.send_json(message)
            except Exception:
                pass


manager = ConnectionManager()


@router.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    """
    General WebSocket endpoint for real-time updates
    Handles: threat alerts, scan progress, system changes
    """
    await manager.connect(websocket, is_admin=False)
    try:
        while True:
            data = await websocket.receive_text()
            try:
                message = json.loads(data)
                if message.get("type") == "ping":
                    await manager.send_personal_message({
                        "type": "pong",
                        "timestamp": datetime.utcnow().isoformat()
                    }, websocket)
            except json.JSONDecodeError:
                pass
    except WebSocketDisconnect:
        manager.disconnect(websocket)


@router.websocket("/ws/admin")
async def websocket_admin_endpoint(websocket: WebSocket):
    """
    Admin WebSocket endpoint for real-time monitoring
    Handles: all device telemetry, threat analytics, system logs
    """
    await manager.connect(websocket, is_admin=True)
    try:
        while True:
            data = await websocket.receive_text()
            try:
                message = json.loads(data)
                if message.get("type") == "ping":
                    await manager.send_personal_message({
                        "type": "pong",
                        "timestamp": datetime.utcnow().isoformat()
                    }, websocket)
                elif message.get("type") == "broadcast_alert":
                    await manager.broadcast(message.get("data", {}))
            except json.JSONDecodeError:
                pass
    except WebSocketDisconnect:
        manager.disconnect(websocket)


async def broadcast_threat_detected(threat_data: Dict[str, Any]):
    """Broadcast threat detection to all connected clients"""
    await manager.broadcast({
        "type": "threat_detected",
        "data": threat_data,
        "timestamp": datetime.utcnow().isoformat()
    })


async def broadcast_scan_progress(scan_data: Dict[str, Any]):
    """Broadcast scan progress updates"""
    await manager.broadcast({
        "type": "scan_progress",
        "data": scan_data,
        "timestamp": datetime.utcnow().isoformat()
    })


async def broadcast_scan_complete(scan_data: Dict[str, Any]):
    """Broadcast scan completion"""
    await manager.broadcast({
        "type": "scan_complete",
        "data": scan_data,
        "timestamp": datetime.utcnow().isoformat()
    })


async def broadcast_device_status(device_data: Dict[str, Any]):
    """Broadcast device status changes"""
    await manager.broadcast({
        "type": "device_status",
        "data": device_data,
        "timestamp": datetime.utcnow().isoformat()
    })


async def broadcast_network_anomaly(anomaly_data: Dict[str, Any]):
    """Broadcast network anomaly detection"""
    await manager.broadcast({
        "type": "network_anomaly",
        "data": anomaly_data,
        "timestamp": datetime.utcnow().isoformat()
    })


async def broadcast_security_alert(alert_data: Dict[str, Any]):
    """Broadcast security alerts to admins"""
    await manager.broadcast_to_admins({
        "type": "security_alert",
        "data": alert_data,
        "timestamp": datetime.utcnow().isoformat()
    })

