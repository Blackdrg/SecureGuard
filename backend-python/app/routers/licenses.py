from fastapi import APIRouter, HTTPException, Depends, status
from sqlalchemy.orm import Session
from pydantic import BaseModel, validator
from typing import Optional
from datetime import datetime, timedelta
from app import database, models, security
from app.database import get_db

router = APIRouter(prefix="/licenses", tags=["licenses"])

class LicenseCreate(BaseModel):
    key: str
    user_id: int
    plan: str = "Pro"
    max_seats: int = 1
    expiry_days: int = 365

class LicenseValidate(BaseModel):
    key: str
    device_id: str

class LicenseResponse(BaseModel):
    id: int
    key_hash: str
    user_id: int
    plan: str
    seats_used: int
    max_seats: int
    expiry: datetime
    valid: bool

@router.post("/")
def create_license(license: LicenseCreate, db: Session = Depends(get_db)):
    # In production, generate key server-side
    hashed_key = security.hash_license_key(license.key)
    db_license = models.License(
        key_hash=hashed_key,
        user_id=license.user_id,
        plan=license.plan,
        max_seats=license.max_seats,
        expiry=datetime.utcnow() + timedelta(days=license.expiry_days),
        seats_used=1
    )
    db.add(db_license)
    db.commit()
    db.refresh(db_license)
    return { "license_id": db_license.id }

@router.get("/{key_hash}")
def get_license(key_hash: str, db: Session = Depends(get_db)):
    license = db.query(models.License).filter(models.License.key_hash == key_hash).first()
    if not license:
        raise HTTPException(status_code=404, detail="License not found")
    return LicenseResponse.from_orm(license)

@router.post("/validate/")
def validate_license(request: LicenseValidate, db: Session = Depends(get_db)):
    license = db.query(models.License).filter(
        models.License.key_hash == security.hash_license_key(request.key),
        models.License.expiry > datetime.utcnow(),
        models.License.seats_used < models.License.max_seats
    ).first()
    
    if license:
        # Update last seen
        license.last_seen = datetime.utcnow()
        db.commit()
        return { "valid": True, "plan": license.plan, "seats_remaining": license.max_seats - license.seats_used }
    raise HTTPException(status_code=401, detail="Invalid or expired license")
