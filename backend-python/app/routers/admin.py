"""
Admin Router
Handles administrative functions and system monitoring
"""

import uuid
from datetime import datetime, timedelta
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy.orm import Session
from sqlalchemy import func
from app.database import get_db
from app.models import User, Device, Threat, Telemetry
from app.routers.auth import get_current_active_user

router = APIRouter()


def require_admin(current_user: User = Depends(get_current_active_user)):
    """Require admin privileges"""
    if not current_user.is_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin privileges required"
        )
    return current_user


class UserAdminResponse(BaseModel):
    id: str
    email: str
    name: Optional[str]
    plan: str
    created_at: datetime
    is_active: bool
    is_admin: bool
    device_count: int = 0

    class Config:
        from_attributes = True


class AdminStats(BaseModel):
    total_users: int
    active_users: int
    total_devices: int
    active_devices: int
    total_threats: int
    threats_today: int


@router.get("/stats", response_model=AdminStats)
async def get_admin_stats(
    current_user: User = Depends(require_admin),
    db: Session = Depends(get_db)
):
    """Get admin statistics"""
    total_users = db.query(User).count()
    active_users = db.query(User).filter(User.is_active == True).count()
    total_devices = db.query(Device).count()
    
    online_threshold = datetime.utcnow() - timedelta(minutes=5)
    active_devices = db.query(Device).filter(
        Device.last_seen >= online_threshold
    ).count()
    
    total_threats = db.query(Threat).count()
    
    today = datetime.utcnow().date()
    threats_today = db.query(Threat).filter(
        func.date(Threat.detected_at) == today
    ).count()
    
    return AdminStats(
        total_users=total_users,
        active_users=active_users,
        total_devices=total_devices,
        active_devices=active_devices,
        total_threats=total_threats,
        threats_today=threats_today
    )


@router.get("/users", response_model=list)
async def list_all_users(
    page: int = 1,
    limit: int = 50,
    current_user: User = Depends(require_admin),
    db: Session = Depends(get_db)
):
    """List all users (admin only)"""
    offset = (page - 1) * limit
    users = db.query(User).offset(offset).limit(limit).all()
    
    result = []
    for user in users:
        device_count = db.query(Device).filter(Device.user_id == user.id).count()
        result.append(UserAdminResponse(
            id=str(user.id),
            email=user.email,
            name=user.name,
            plan=user.plan,
            created_at=user.created_at,
            is_active=user.is_active,
            is_admin=user.is_admin,
            device_count=device_count
        ))
    
    return result


@router.post("/users/{user_id}/suspend")
async def suspend_user(
    user_id: str,
    current_user: User = Depends(require_admin),
    db: Session = Depends(get_db)
):
    """Suspend a user account"""
    user = db.query(User).filter(User.id == uuid.UUID(user_id)).first()
    
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    
    if user.id == current_user.id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot suspend yourself"
        )
    
    user.is_active = False
    db.commit()
    
    return {"message": f"User {user.email} has been suspended"}


@router.post("/users/{user_id}/activate")
async def activate_user(
    user_id: str,
    current_user: User = Depends(require_admin),
    db: Session = Depends(get_db)
):
    """Activate a user account"""
    user = db.query(User).filter(User.id == uuid.UUID(user_id)).first()
    
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    
    user.is_active = True
    db.commit()
    
    return {"message": f"User {user.email} has been activated"}


@router.get("/devices")
async def list_all_devices(
    status_filter: Optional[str] = None,
    page: int = 1,
    limit: int = 50,
    current_user: User = Depends(require_admin),
    db: Session = Depends(get_db)
):
    """List all devices (admin only)"""
    offset = (page - 1) * limit
    query = db.query(Device)
    
    if status_filter:
        query = query.filter(Device.status == status_filter)
    
    devices = query.offset(offset).limit(limit).all()
    
    result = []
    for device in devices:
        user = db.query(User).filter(User.id == device.user_id).first()
        result.append({
            "id": str(device.id),
            "device_name": device.device_name,
            "device_type": device.device_type,
            "os_version": device.os_version,
            "status": device.status,
            "last_seen": device.last_seen,
            "user_email": user.email if user else "Unknown"
        })
    
    return result


@router.get("/threats/recent")
async def get_recent_threats(
    limit: int = 20,
    current_user: User = Depends(require_admin),
    db: Session = Depends(get_db)
):
    """Get recent threats across all users"""
    threats = db.query(Threat).order_by(
        Threat.detected_at.desc()
    ).limit(limit).all()
    
    result = []
    for threat in threats:
        device = db.query(Device).filter(Device.id == threat.device_id).first()
        result.append({
            "id": str(threat.id),
            "threat_name": threat.threat_name,
            "threat_type": threat.threat_type,
            "severity": threat.severity,
            "detected_at": threat.detected_at,
            "device_name": device.device_name if device else "Unknown"
        })
    
    return result
