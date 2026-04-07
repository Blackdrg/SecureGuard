"""
Users Router
Handles user profile and account management
"""

import uuid
from datetime import datetime
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy.orm import Session
from app.database import get_db
from app.models import User
from app.routers.auth import get_current_active_user

router = APIRouter()


class UserProfileUpdate(BaseModel):
    name: Optional[str] = None


class PasswordChange(BaseModel):
    current_password: str
    new_password: str


class UserProfileResponse(BaseModel):
    id: str
    email: str
    name: Optional[str]
    plan: str
    created_at: datetime
    is_active: bool

    class Config:
        from_attributes = True


@router.get("/profile", response_model=UserProfileResponse)
async def get_profile(
    current_user: User = Depends(get_current_active_user)
):
    """Get current user profile"""
    return current_user


@router.put("/profile")
async def update_profile(
    profile_update: UserProfileUpdate,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """Update user profile"""
    if profile_update.name:
        current_user.name = profile_update.name

    db.commit()
    db.refresh(current_user)
    return {"message": "Profile updated successfully"}


@router.post("/change-password")
async def change_password(
    password_change: PasswordChange,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """Change user password"""
    from app.routers.auth import verify_password, get_password_hash

    if not verify_password(password_change.current_password, current_user.password_hash):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Current password is incorrect"
        )

    if len(password_change.new_password) < 8:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="New password must be at least 8 characters"
        )

    current_user.password_hash = get_password_hash(password_change.new_password)
    db.commit()
    return {"message": "Password changed successfully"}


@router.get("/devices/count")
async def get_device_count(
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """Get device count for current user"""
    from app.models import Device
    count = db.query(Device).filter(Device.user_id == current_user.id).count()
    return {"device_count": count, "plan": current_user.plan}
