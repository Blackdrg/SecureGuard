"""
Devices Router
Handles device registration, management, and synchronization
"""

import uuid
import secrets
from datetime import datetime
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy.orm import Session
from app.database import get_db
from app.models import User, Device, Telemetry, ScanHistory
from app.routers.auth import get_current_active_user

router = APIRouter()


# Pydantic schemas
class DeviceCreate(BaseModel):
    device_name: str
    device_type: str = "desktop"
    os_version: str
    cpu_count: int
    total_ram_mb: int
    app_version: str


class DeviceResponse(BaseModel):
    id: str
    device_name: str
    device_type: str
    os_version: str
    status: str
    last_seen: datetime
    app_version: Optional[str]
    signature_version: Optional[str]

    class Config:
        from_attributes = True


class DeviceRegistrationResponse(BaseModel):
    device_id: str
    registration_token: str
    message: str


class TelemetryData(BaseModel):
    cpu_usage: int
    ram_usage: int
    disk_usage: int
    network_connections: int
    processes_count: int
    security_score: int
    active_threats: int = 0


class ScanHistoryCreate(BaseModel):
    scan_type: str
    files_scanned: int
    threats_found: int
    duration_seconds: int
    scan_path: Optional[str] = None


class DeviceUpdate(BaseModel):
    device_name: Optional[str] = None
    status: Optional[str] = None


@router.post("/register", response_model=DeviceRegistrationResponse)
async def register_device(
    device_data: DeviceCreate,
    registration_token: str,
    db: Session = Depends(get_db)
):
    """Register a new device using registration token"""
    device = db.query(Device).filter(
        Device.registration_token == registration_token
    ).first()

    if not device:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Invalid registration token"
        )

    device.device_name = device_data.device_name
    device.device_type = device_data.device_type
    device.os_version = device_data.os_version
    device.cpu_count = device_data.cpu_count
    device.total_ram_mb = device_data.total_ram_mb
    device.app_version = device_data.app_version
    device.status = "active"
    device.last_seen = datetime.utcnow()
    device.device_token = secrets.token_urlsafe(32)

    db.commit()
    db.refresh(device)

    return DeviceRegistrationResponse(
        device_id=str(device.id),
        registration_token=device.registration_token,
        message="Device registered successfully"
    )


@router.get("/", response_model=List[DeviceResponse])
async def list_devices(
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """List all devices for current user"""
    devices = db.query(Device).filter(Device.user_id == current_user.id).all()
    return devices


@router.get("/{device_id}", response_model=DeviceResponse)
async def get_device(
    device_id: str,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """Get device details"""
    device = db.query(Device).filter(
        Device.id == uuid.UUID(device_id),
        Device.user_id == current_user.id
    ).first()

    if not device:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Device not found"
        )
    return device


@router.put("/{device_id}")
async def update_device(
    device_id: str,
    device_update: DeviceUpdate,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """Update device information"""
    device = db.query(Device).filter(
        Device.id == uuid.UUID(device_id),
        Device.user_id == current_user.id
    ).first()

    if not device:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Device not found"
        )

    if device_update.device_name:
        device.device_name = device_update.device_name
    if device_update.status:
        device.status = device_update.status

    device.last_seen = datetime.utcnow()
    db.commit()
    return {"message": "Device updated successfully"}


@router.delete("/{device_id}")
async def delete_device(
    device_id: str,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """Delete a device"""
    device = db.query(Device).filter(
        Device.id == uuid.UUID(device_id),
        Device.user_id == current_user.id
    ).first()

    if not device:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Device not found"
        )

    db.delete(device)
    db.commit()
    return {"message": "Device deleted successfully"}


@router.post("/create-registration-token")
async def create_registration_token(
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """Create a new registration token for device pairing"""
    token = secrets.token_urlsafe(32)
    device = Device(
        id=uuid.uuid4(),
        user_id=current_user.id,
        device_name="New Device",
        registration_token=token,
        status="pending"
    )
    db.add(device)
    db.commit()
    return {
        "registration_token": token,
        "expires_in": 3600
    }


@router.post("/api/telemetry")
async def receive_telemetry(
    device_id: str,
    device_token: str,
    telemetry: TelemetryData,
    db: Session = Depends(get_db)
):
    """Receive telemetry from device"""
    device = db.query(Device).filter(
        Device.id == uuid.UUID(device_id),
        Device.device_token == device_token
    ).first()

    if not device:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid device credentials"
        )

    telemetry_record = Telemetry(
        id=uuid.uuid4(),
        device_id=device.id,
        recorded_at=datetime.utcnow(),
        cpu_usage=telemetry.cpu_usage,
        ram_usage=telemetry.ram_usage,
        disk_usage=telemetry.disk_usage,
        network_connections=telemetry.network_connections,
        processes_count=telemetry.processes_count,
        security_score=telemetry.security_score,
        active_threats=telemetry.active_threats
    )

    db.add(telemetry_record)
    device.last_seen = datetime.utcnow()
    device.cpu_usage = telemetry.cpu_usage
    device.ram_usage = telemetry.ram_usage
    device.disk_usage = telemetry.disk_usage
    db.commit()
    return {"status": "success"}


@router.post("/api/scan-history")
async def receive_scan_history(
    device_id: str,
    device_token: str,
    scan_data: ScanHistoryCreate,
    db: Session = Depends(get_db)
):
    """Receive scan history from device"""
    device = db.query(Device).filter(
        Device.id == uuid.UUID(device_id),
        Device.device_token == device_token
    ).first()

    if not device:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid device credentials"
        )

    scan_record = ScanHistory(
        id=uuid.uuid4(),
        device_id=device.id,
        scan_type=scan_data.scan_type,
        files_scanned=scan_data.files_scanned,
        threats_found=scan_data.threats_found,
        duration_seconds=scan_data.duration_seconds,
        completed_at=datetime.utcnow(),
        scan_path=scan_data.scan_path
    )

    db.add(scan_record)
    db.commit()
    return {"status": "success"}


@router.get("/api/status/{device_id}")
async def get_device_status(
    device_id: str,
    device_token: str,
    db: Session = Depends(get_db)
):
    """Get device sync status"""
    device = db.query(Device).filter(
        Device.id == uuid.UUID(device_id),
        Device.device_token == device_token
    ).first()

    if not device:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid device credentials"
        )

    latest = db.query(Telemetry).filter(
        Telemetry.device_id == device.id
    ).order_by(Telemetry.recorded_at.desc()).first()

    return {
        "device_id": str(device.id),
        "device_name": device.device_name,
        "status": device.status,
        "last_seen": device.last_seen,
        "latest_telemetry": {
            "cpu_usage": latest.cpu_usage if latest else None,
            "ram_usage": latest.ram_usage if latest else None,
            "security_score": latest.security_score if latest else None
        } if latest else None
    }
