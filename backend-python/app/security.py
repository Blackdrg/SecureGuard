"""
SecureGuard Security Middleware
Provides CSRF protection, rate limiting, and security headers
"""

import secrets
import hashlib
import re
from datetime import timedelta
from fastapi import Request, status
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
from slowapi import Limiter
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from starlette.middleware.cors import CORSMiddleware
from starlette.types import ASGIApp

# Rate limiter instance
limiter = Limiter(key_func=get_remote_address)


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Add security headers to all responses"""

    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)

        # Security headers
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        csp = (
            "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; "
            "style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; "
            "font-src 'self'; connect-src 'self' https: wss:; frame-ancestors 'none';"
        )
        response.headers["Content-Security-Policy"] = csp

        return response


class CSRFMiddleware(BaseHTTPMiddleware):
    """CSRF Protection Middleware"""

    def __init__(self, app: ASGIApp, secret_key: str = None):
        super().__init__(app)
        self.secret_key = secret_key or secrets.token_hex(32)
        self.csrf_tokens = {}

    def _generate_csrf_token(self) -> str:
        """Generate a secure CSRF token"""
        token = secrets.token_urlsafe(32)
        token_hash = hashlib.sha256(
            f"{token}{self.secret_key}".encode()
        ).hexdigest()
        return f"{token}:{token_hash}"

    def _validate_csrf_token(self, token: str) -> bool:
        """Validate CSRF token"""
        if not token or ':' not in token:
            return False

        try:
            token_value, token_hash = token.split(':', 1)
            expected_hash = hashlib.sha256(
                f"{token_value}{self.secret_key}".encode()
            ).hexdigest()
            return secrets.compare_digest(token_hash, expected_hash)
        except Exception:
            return False

    async def dispatch(self, request: Request, call_next):
        # Skip CSRF for safe methods
        if request.method in ["GET", "HEAD", "OPTIONS"]:
            response = await call_next(request)
            # Add CSRF token to response headers for GET requests
            if request.method == "GET":
                csrf_token = self._generate_csrf_token()
                response.headers["X-CSRF-Token"] = csrf_token
            return response

        # Check CSRF token for state-changing methods
        csrf_token = request.headers.get("X-CSRF-Token") or request.cookies.get("csrf_token")

        # Skip CSRF for API keys (they should use other auth methods)
        auth_header = request.headers.get("Authorization", "")
        if auth_header.startswith("ApiKey ") or auth_header.startswith("Bearer "):
            pass

        # Validate CSRF token
        if not self._validate_csrf_token(csrf_token or ""):
            return JSONResponse(
                status_code=status.HTTP_403_FORBIDDEN,
                content={"detail": "CSRF token validation failed"}
            )

        response = await call_next(request)
        return response


class InputValidationMiddleware(BaseHTTPMiddleware):
    """Input validation and sanitization"""

    # Blocked patterns that may indicate malicious input
    BLOCKED_PATTERNS = [
        r"<script[^>]*>",
        r"javascript:",
        r"on\w+\s*=",
        r"eval\s*\(",
        r"expression\s*\(",
        r"<!--",
        r"-->",
    ]

    async def dispatch(self, request: Request, call_next):
        # Skip for GET requests
        if request.method == "GET":
            return await call_next(request)

        # Check request body for malicious patterns
        content_type = request.headers.get("content-type", "")

        if "application/json" in content_type:
            try:
                body = await request.body()
                if body:
                    body_str = body.decode("utf-8", errors="ignore")
                    # Basic validation - check for common XSS patterns
                    for pattern in self.BLOCKED_PATTERNS:
                        if re.search(pattern, body_str, re.IGNORECASE):
                            return JSONResponse(
                                status_code=status.HTTP_400_BAD_REQUEST,
                                content={"detail": "Invalid input detected"}
                            )
            except Exception:
                pass

        response = await call_next(request)
        return response


def create_rate_limit_exceeded_handler():
    """Create rate limit exceeded handler"""
    async def rate_limit_exceeded_handler(request: Request, exc: RateLimitExceeded):
        return JSONResponse(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            content={
                "detail": "Rate limit exceeded",
                "retry_after": exc.detail
            },
            headers={"Retry-After": str(60)}
        )
    return rate_limit_exceeded_handler


def get_cors_config():
    """Get secure CORS configuration"""
    return {
        "allow_origins": [
            "https://localhost",
            "https://localhost:443",
            "https://127.0.0.1",
        ],
        "allow_origin_regex": r"https?://localhost:\d+",
        "allow_credentials": True,
        "allow_methods": ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
        "allow_headers": [
            "Content-Type",
            "Authorization",
            "X-CSRF-Token",
            "X-Requested-With",
            "Accept",
            "Accept-Language",
            "Content-Language",
        ],
        "expose_headers": ["X-CSRF-Token"],
        "max_age": 600,
    }


class SecureAPIMiddleware:
    """Combined security middleware for API protection"""

    @staticmethod
    def create_middleware(app: ASGIApp):
        """Create combined middleware stack"""
        middleware = CORSMiddleware(
            app=app,
            **get_cors_config()
        )
        return middleware

