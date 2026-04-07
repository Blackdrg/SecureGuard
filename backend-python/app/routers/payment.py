"""Payment Router - Stub for SecureGuard payment integration
Supports Stripe/PayPal simulation"""

from fastapi import APIRouter, HTTPException, Depends, status
from pydantic import BaseModel
from typing import Optional
from datetime import datetime, timedelta
from app.database import get_db
from app.models import User
from app.routers.auth import get_current_active_user
import uuid
import stripe  # pip install stripe (optional for real)

router = APIRouter(prefix="/api/payment", tags=["payment"])

class SubscriptionRequest(BaseModel):
    email: str
    plan: str
    payment_method: str = "card"

class PaymentRequest(BaseModel):
    email: str
    amount: float
    currency: str = "USD"
    payment_method: str = "card"
    plan: str = "pro"

class PaymentResult(BaseModel):
    success: bool
    subscription_id: Optional[str] = None
    transaction_id: Optional[str] = None
    message: str = ""

# Stripe key (demo)
stripe.api_key = "sk_test_demo_key"

@router.post("/subscribe", response_model=PaymentResult)
async def create_subscription(request: SubscriptionRequest, current_user = Depends(get_current_active_user)):
    """Create subscription"""
    try:
        subscription_id = str(uuid.uuid4())
        # Simulate Stripe subscription
        # stripe.Subscription.create(...)
        
        return PaymentResult(
            success=True,
            subscription_id=subscription_id,
            message=f"Subscription {request.plan} created successfully"
        )
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@router.post("/process", response_model=PaymentResult)
async def process_payment(request: PaymentRequest):
    """Process payment"""
    try:
        transaction_id = str(uuid.uuid4())
        # Simulate Stripe payment
        # stripe.PaymentIntent.create(...)
        
        return PaymentResult(
            success=True,
            transaction_id=transaction_id,
            message=f"Payment of ${request.amount} processed"
        )
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@router.get("/{subscription_id}", response_model=Subscription)
async def get_subscription(subscription_id: str):
    """Get subscription details"""
    # Simulate DB lookup
    return Subscription(
        id=subscription_id,
        user_email="user@example.com",
        plan="pro",
        start_date=datetime.utcnow(),
        end_date=datetime.utcnow() + timedelta(days=30),
        status="active",
        auto_renew=True
    )

class Subscription(BaseModel):
    id: str
    user_email: str
    plan: str
    start_date: datetime
    end_date: datetime
    status: str
    auto_renew: bool

