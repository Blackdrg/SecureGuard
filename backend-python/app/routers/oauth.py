"""
SecureGuard OAuth2/OpenID Connect Module
Provides OAuth2 authentication with PKCE support
"""

import secrets
import hashlib
import urllib.parse
from typing import Optional, Dict, Any
from datetime import datetime, timedelta
from pydantic import BaseModel
from fastapi import APIRouter, Depends, HTTPException, status, Request
from fastapi.responses import RedirectResponse, JSONResponse
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import User
from app.config import settings

router = APIRouter()


# OAuth2 Client Configuration
OAUTH_CLIENTS = {
    "google": {
        "client_id": "your-google-client-id",
        "client_secret": "your-google-client-secret",
        "authorization_url": "https://accounts.google.com/o/oauth2/v2/auth",
        "token_url": "https://oauth2.googleapis.com/token",
        "userinfo_url": "https://www.googleapis.com/oauth2/v2/userinfo",
        "scope": "openid email profile"
    },
    "microsoft": {
        "client_id": "your-microsoft-client-id",
        "client_secret": "your-microsoft-client-secret",
        "authorization_url": "https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
        "token_url": "https://login.microsoftonline.com/common/oauth2/v2.0/token",
        "userinfo_url": "https://graph.microsoft.com/v1.0/me",
        "scope": "openid email profile User.Read"
    },
    "github": {
        "client_id": "your-github-client-id",
        "client_secret": "your-github-client-secret",
        "authorization_url": "https://github.com/login/oauth/authorize",
        "token_url": "https://github.com/login/oauth/access_token",
        "userinfo_url": "https://api.github.com/user",
        "scope": "read:user user:email"
    }
}


class PKCEChallenge:
    """PKCE (Proof Key for Code Exchange) handler"""
    
    @staticmethod
    def generate_code_verifier(length: int = 128) -> str:
        """Generate a code verifier"""
        return secrets.token_urlsafe(length)[:length]
    
    @staticmethod
    def generate_code_challenge(verifier: str) -> str:
        """Generate a code challenge from verifier"""
        digest = hashlib.sha256(verifier.encode()).digest()
        return urllib.parse.quote_base64(digest).rstrip('=')
    
    @staticmethod
    def generate_state() -> str:
        """Generate random state parameter"""
        return secrets.token_urlsafe(32)


class OAuthStateStore:
    """Store OAuth state for security"""
    states: Dict[str, Dict[str, Any]] = {}
    
    @classmethod
    def create(cls, provider: str, redirect_uri: str) -> str:
        """Create and store OAuth state"""
        state = PKCEChallenge.generate_state()
        code_verifier = PKCEChallenge.generate_code_verifier()
        
        cls.states[state] = {
            "provider": provider,
            "redirect_uri": redirect_uri,
            "code_verifier": code_verifier,
            "created_at": datetime.utcnow(),
            "expires_at": datetime.utcnow() + timedelta(minutes=10)
        }
        
        return state
    
    @classmethod
    def get(cls, state: str) -> Optional[Dict[str, Any]]:
        """Get OAuth state"""
        state_data = cls.states.get(state)
        
        if not state_data:
            return None
            
        # Check expiration
        if datetime.utcnow() > state_data["expires_at"]:
            del cls.states[state]
            return None
            
        return state_data
    
    @classmethod
    def delete(cls, state: str) -> None:
        """Delete OAuth state"""
        if state in cls.states:
            del cls.states[state]


# OAuth2 Schemas
class OAuthCallbackRequest(BaseModel):
    """OAuth callback request"""
    code: str
    state: str
    error: Optional[str] = None
    error_description: Optional[str] = None


class OAuthProvidersResponse(BaseModel):
    """Available OAuth providers"""
    providers: list[str]


class TokenResponse(BaseModel):
    """OAuth token response"""
    access_token: str
    token_type: str
    expires_in: int
    refresh_token: Optional[str] = None
    id_token: Optional[str] = None


class OAuthUserInfo(BaseModel):
    """OAuth user information"""
    sub: str
    email: Optional[str] = None
    name: Optional[str] = None
    picture: Optional[str] = None


# OAuth2 Endpoints
@router.get("/providers", response_model=OAuthProvidersResponse)
async def get_oauth_providers():
    """Get available OAuth providers"""
    return OAuthProvidersResponse(
        providers=list(OAUTH_CLIENTS.keys())
    )


@router.get("/authorize/{provider}")
async def oauth_authorize(
    provider: str,
    request: Request,
    redirect_uri: Optional[str] = None
):
    """Initiate OAuth2 authorization flow with PKCE"""
    
    # Validate provider
    if provider not in OAUTH_CLIENTS:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unknown provider: {provider}"
        )
    
    client = OAUTH_CLIENTS[provider]
    
    # Default redirect URI
    base_url = str(request.base_url).rstrip('/')
    if not redirect_uri:
        redirect_uri = f"{base_url}/api/auth/oauth/callback/{provider}"
    
    # Generate PKCE values
    state = OAuthStateStore.create(provider, redirect_uri)
    code_verifier = OAuthStateStore.states[state]["code_verifier"]
    code_challenge = PKCEChallenge.generate_code_challenge(code_verifier)
    
    # Build authorization URL
    params = {
        "client_id": client["client_id"],
        "redirect_uri": redirect_uri,
        "response_type": "code",
        "scope": client["scope"],
        "state": state,
        "code_challenge": code_challenge,
        "code_challenge_method": "S256"
    }
    
    auth_url = f"{client['authorization_url']}?{urllib.parse.urlencode(params)}"
    
    return RedirectResponse(url=auth_url)


@router.get("/callback/{provider}")
async def oauth_callback(
    provider: str,
    code: str,
    state: str,
    error: Optional[str] = None
):
    """Handle OAuth2 callback"""
    
    # Check for error
    if error:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"OAuth error: {error}"
        )
    
    # Validate state
    state_data = OAuthStateStore.get(state)
    if not state_data:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired state"
        )
    
    if state_data["provider"] != provider:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Provider mismatch"
        )
    
    # Exchange code for tokens
    try:
        client = OAUTH_CLIENTS[provider]
        
        # Build token request
        token_params = {
            "client_id": client["client_id"],
            "client_secret": client["client_secret"],
            "code": code,
            "grant_type": "authorization_code",
            "redirect_uri": state_data["redirect_uri"],
            "code_verifier": state_data["code_verifier"]
        }
        
        # In production, use httpx to make the request
        # For now, return a placeholder
        return {
            "status": "success",
            "message": "OAuth flow completed. Token exchange would happen here.",
            "provider": provider
        }
        
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Token exchange failed: {str(e)}"
        )
    finally:
        # Clean up state
        OAuthStateStore.delete(state)


@router.post("/token")
async def oauth_token_exchange(
    grant_type: str,
    code: Optional[str] = None,
    refresh_token: Optional[str] = None,
    client_id: Optional[str] = None,
    client_secret: Optional[str] = None
):
    """Exchange OAuth tokens"""
    
    if grant_type == "authorization_code":
        if not code:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Code required"
            )
        # Token exchange logic would go here
        pass
    elif grant_type == "refresh_token":
        if not refresh_token:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Refresh token required"
            )
        # Refresh token logic would go here
        pass
    else:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Unsupported grant type"
        )
    
    return {
        "access_token": "placeholder",
        "token_type": "bearer",
        "expires_in": 3600
    }


# OpenID Connect Discovery
@router.get("/.well-known/openid-configuration")
async def openid_configuration():
    """OpenID Connect discovery endpoint"""
    return {
        "issuer": "https://api.secureguard.local",
        "authorization_endpoint": "https://api.secureguard.local/api/auth/oauth/authorize/google",
        "token_endpoint": "https://api.secureguard.local/api/auth/oauth/token",
        "userinfo_endpoint": "https://api.secureguard.local/api/auth/oauth/userinfo",
        "jwks_uri": "https://api.secureguard.local/api/auth/oauth/keys",
        "response_types_supported": ["code"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["RS256"],
        "scopes_supported": ["openid", "profile", "email"],
        "token_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post"],
        "claims_supported": [
            "sub", "iss", "aud", "exp", "iat", "email", "email_verified", "name"
        ]
    }


@router.get("/oauth/keys")
async def oauth_jwks():
    """JSON Web Key Set for OAuth"""
    # In production, return actual JWKS
    return {
        "keys": []
    }


@router.get("/oauth/userinfo")
async def oauth_userinfo(request: Request):
    """Get current user info from OAuth provider"""
    # In production, validate token and fetch user info
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authorization header"
        )
    
    return {
        "sub": "placeholder",
        "email": "user@example.com",
        "name": "User Name"
    }

