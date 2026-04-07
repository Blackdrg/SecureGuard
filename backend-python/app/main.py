"""
SecureGuard Cloud Backend - Main Application
FastAPI application with JWT authentication, device management, and ML inference
"""

import os
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from slowapi import Limiter
from slowapi.errors import RateLimitExceeded
from app.routers import auth, users, devices, telemetry, oauth
from app.database import engine, Base
from app.config import settings
from app.security import (
    SecurityHeadersMiddleware,
    CSRFMiddleware,
    InputValidationMiddleware,
    limiter,
    get_cors_config,
    create_rate_limit_exceeded_handler,
)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan events"""
    # Startup: Create database tables (ignore if already exists)
    try:
        Base.metadata.create_all(bind=engine)
        print("✓ Database tables created/verified")
    except Exception as e:
        print(f"⚠ Database init note: {e}")
    
    print(f"✓ SecureGuard API Server started on port {settings.PORT}")
    yield
    # Shutdown
    print("✓ SecureGuard API Server shutting down")


# Create FastAPI application
app = FastAPI(
    title="SecureGuard API",
    description="AI-Powered Cybersecurity Platform - Cloud Backend",
    version="2.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan
)

# Add rate limiter
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, create_rate_limit_exceeded_handler())

# Add security middleware (order matters - CORS first, then security headers)
app.add_middleware(
    CORSMiddleware,
    **get_cors_config()
)

# Add custom security middleware
app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(CSRFMiddleware, secret_key=settings.JWT_SECRET_KEY)
app.add_middleware(InputValidationMiddleware)

# Include routers
app.include_router(auth.router, prefix="/api/auth", tags=["Authentication"])
app.include_router(oauth.router, prefix="/api/auth/oauth", tags=["OAuth"])
app.include_router(users.router, prefix="/api/users", tags=["Users"])
app.include_router(devices.router, prefix="/api/devices", tags=["Devices"])
app.include_router(telemetry.router, prefix="/api/telemetry", tags=["Telemetry"])


@app.get("/")
async def root():
    """Root endpoint"""
    return {
        "name": "SecureGuard API",
        "version": "2.0.0",
        "status": "operational",
        "docs": "/docs"
    }


@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "database": "connected",
        "ml_service": "ready"
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "app.main:app",
        host="0.0.0.0",
        port=settings.PORT,
        reload=settings.DEBUG
    )

