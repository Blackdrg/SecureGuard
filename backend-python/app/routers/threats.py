"""
Threats Router
Handles threat data synchronization and management
"""

import uuid
from datetime import datetime, timedelta
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy.orm import Session
from sqlalchemy import desc
from app.database import get_db
from app.models import User, Device, Threat
from app.routers.auth import get_current_active_user

router = APIRouter()


class ThreatCreate(BaseModel):
    threat_name: str
    threat_type: str
    file_path: Optional[str] = None
    file_hash: Optional[str] = None
    severity: str
    action_taken: str
    detection_method: Optional[str] = None


class ThreatResponse(BaseModel):
    id: str
    threat_name: str
    threat_type: str
    file_path: Optional[str]
    file_hash: Optional[str]
    severity: str
    action_taken: str
    detected_at: datetime
    detection_method: Optional[str]

    class Config:
        from_attributes = True


class ThreatStats(BaseModel):
    total_threats: int
    threats_today: int
    threats_this_week: int
    by_severity: dict
    by_type: dict


# Device API endpoints (called from desktop app)
@router.post("/api/sync")
async def sync_threats(
    device_id: str,
    device_token: str,
    threats: List[ThreatCreate],
    db: Session = Depends(get_db)
):
    """Sync threats from device"""
    device = db.query(Device).filter(
        Device.id == uuid.UUID(device_id),
        Device.device_token == device_token
    ).first()

    if not device:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid device credentials"
        )

    synced_count = 0
    for threat_data in threats:
        threat = Threat(
            id=uuid.uuid4(),
            device_id=device.id,
            user_id=device.user_id,
            threat_name=threat_data.threat_name,
            threat_type=threat_data.threat_type,
            file_path=threat_data.file_path,
            file_hash=threat_data.file_hash,
            severity=threat_data.severity,
            action_taken=threat_data.action_taken,
            detection_method=threat_data.detection_method,
            detected_at=datetime.utcnow(),
            synced_to_cloud=True
        )
        db.add(threat)
        synced_count += 1

    db.commit()
    return {"synced": synced_count, "status": "success"}


# User-facing endpoints
@router.get("/", response_model=List[ThreatResponse])
async def list_threats(
    device_id: Optional[str] = None,
    severity: Optional[str] = None,
    limit: int = 50,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """List threats for current user"""
    query = db.query(Threat).filter(Threat.user_id == current_user.id)

    if device_id:
        query = query.filter(Threat.device_id == uuid.UUID(device_id))
    if severity:
        query = query.filter(Threat.severity == severity)

    threats = query.order_by(desc(Threat.detected_at)).limit(limit).all()
    return threats


@router.get("/stats", response_model=ThreatStats)
async def get_threat_stats(
    device_id: Optional[str] = None,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """Get threat statistics"""
    query = db.query(Threat).filter(Threat.user_id == current_user.id)

    if device_id:
        query = query.filter(Threat.device_id == uuid.UUID(device_id))

    all_threats = query.all()
    total_threats = len(all_threats)

    today = datetime.utcnow().date()
    week_ago = datetime.utcnow() - timedelta(days=7)

    threats_today = sum(1 for t in all_threats if t.detected_at.date() >= today)
    threats_this_week = sum(1 for t in all_threats if t.detected_at >= week_ago)

    # Group by severity
    by_severity = {}
    for threat in all_threats:
        by_severity[threat.severity] = by_severity.get(threat.severity, 0) + 1

    # Group by type
    by_type = {}
    for threat in all_threats:
        by_type[threat.threat_type] = by_type.get(threat.threat_type, 0) + 1

    return ThreatStats(
        total_threats=total_threats,
        threats_today=threats_today,
        threats_this_week=threats_this_week,
        by_severity=by_severity,
        by_type=by_type
    )


@router.delete("/{threat_id}")
async def delete_threat(
    threat_id: str,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """Delete a threat record"""
    threat = db.query(Threat).filter(
        Threat.id == uuid.UUID(threat_id),
        Threat.user_id == current_user.id
    ).first()

    if not threat:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Threat not found"
        )

    db.delete(threat)
    db.commit()
    return {"message": "Threat deleted successfully"}
