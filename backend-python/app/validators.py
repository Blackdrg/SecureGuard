"""
SecureGuard Input Validation Schemas
Pydantic models for request validation
"""

import re
from typing import Optional, List, Any
from pydantic import BaseModel, Field, field_validator, model_validator
from pydantic.types import constr


# Custom constraints
EmailStr = constr(pattern=r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$")
PasswordStr = constr(min_length=8, max_length=128)
UsernameStr = constr(min_length=3, max_length=50, pattern=r"^[a-zA-Z0-9_-]+$")


class EmailValidationModel(BaseModel):
    """Email validation with strict patterns"""
    email: str
    
    @field_validator('email')
    @classmethod
    def validate_email(cls, v: str) -> str:
        pattern = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
        if not re.match(pattern, v):
            raise ValueError('Invalid email format')
        return v.lower()


class UserRegistrationSchema(BaseModel):
    """User registration validation"""
    email: str = Field(..., description="User email address")
    password: str = Field(..., description="User password", min_length=8, max_length=128)
    name: Optional[str] = Field(None, max_length=100)
    
    @field_validator('email')
    @classmethod
    def validate_email(cls, v: str) -> str:
        pattern = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
        if not re.match(pattern, v):
            raise ValueError('Invalid email format')
        return v.lower()
    
    @field_validator('password')
    @classmethod
    def validate_password(cls, v: str) -> str:
        # Check for password strength
        if not re.search(r"[A-Z]", v):
            raise ValueError('Password must contain at least one uppercase letter')
        if not re.search(r"[a-z]", v):
            raise ValueError('Password must contain at least one lowercase letter')
        if not re.search(r"[0-9]", v):
            raise ValueError('Password must contain at least one digit')
        return v
    
    @field_validator('name')
    @classmethod
    def validate_name(cls, v: Optional[str]) -> Optional[str]:
        if v is not None:
            # Sanitize name - remove special characters
            v = re.sub(r'[^\w\s-]', '', v)
            v = v.strip()
        return v


class UserLoginSchema(BaseModel):
    """User login validation"""
    email: str = Field(..., description="User email")
    password: str = Field(..., description="User password")
    
    @field_validator('email')
    @classmethod
    def validate_email(cls, v: str) -> str:
        return v.lower().strip()


class SettingsUpdateSchema(BaseModel):
    """Settings update validation"""
    real_time_protection: Optional[bool] = None
    ransomware_shield: Optional[bool] = None
    network_protection: Optional[bool] = None
    usb_scan: Optional[bool] = None
    privacy_protection: Optional[bool] = None
    cloud_intelligence: Optional[bool] = None
    behavioral_monitoring: Optional[bool] = None
    web_protection: Optional[bool] = None
    auto_update: Optional[bool] = None
    start_with_windows: Optional[bool] = None
    show_notifications: Optional[bool] = None
    
    @model_validator(mode='before')
    @classmethod
    def validate_settings(cls, values: dict) -> dict:
        # Ensure only boolean values
        for key, value in values.items():
            if value is not None and not isinstance(value, bool):
                raise ValueError(f'{key} must be a boolean')
        return values


class ScanRequestSchema(BaseModel):
    """Scan request validation"""
    scan_type: str = Field(..., description="Type of scan to perform")
    
    @field_validator('scan_type')
    @classmethod
    def validate_scan_type(cls, v: str) -> str:
        allowed_types = ['quick', 'full', 'custom', 'memory', 'registry']
        if v not in allowed_types:
            raise ValueError(f'Scan type must be one of: {", ".join(allowed_types)}')
        return v


class ProtectionModeSchema(BaseModel):
    """Protection mode update validation"""
    mode: str = Field(..., description="Protection mode")
    
    @field_validator('mode')
    @classmethod
    def validate_mode(cls, v: str) -> str:
        allowed_modes = ['normal', 'strict', 'permissive', 'autopilot']
        if v not in allowed_modes:
            raise ValueError(f'Mode must be one of: {", ".join(allowed_modes)}')
        return v


class AssistantQuerySchema(BaseModel):
    """Security assistant query validation"""
    query: str = Field(..., min_length=1, max_length=1000)
    
    @field_validator('query')
    @classmethod
    def sanitize_query(cls, v: str) -> str:
        # Remove potentially dangerous patterns
        v = v.strip()
        # Limit to reasonable length
        if len(v) > 1000:
            raise ValueError('Query must be less than 1000 characters')
        return v


class SelfHealingRequestSchema(BaseModel):
    """Self-healing request validation"""
    action: str = Field(..., description="Action to perform")
    options: Optional[dict] = None
    
    @field_validator('action')
    @classmethod
    def validate_action(cls, v: str) -> str:
        allowed_actions = ['repair', 'snapshot', 'restore', 'rollback']
        if v not in allowed_actions:
            raise ValueError(f'Action must be one of: {", ".join(allowed_actions)}')
        return v


class IdentityScanRequestSchema(BaseModel):
    """Identity scan request validation"""
    action: str = Field(..., description="Action to perform")
    
    @field_validator('action')
    @classmethod
    def validate_action(cls, v: str) -> str:
        allowed_actions = ['start', 'stop', 'status']
        if v not in allowed_actions:
            raise ValueError(f'Action must be one of: {", ".join(allowed_actions)}')
        return v


class ModuleToggleSchema(BaseModel):
    """Module toggle validation"""
    module_id: str = Field(..., description="Module identifier")
    enabled: bool = Field(..., description="Enable or disable module")
    
    @field_validator('module_id')
    @classmethod
    def validate_module_id(cls, v: str) -> str:
        # Only allow alphanumeric and underscores
        if not re.match(r'^[a-zA-Z0-9_]+$', v):
            raise ValueError('Module ID must contain only letters, numbers, and underscores')
        return v


class SimulationRequestSchema(BaseModel):
    """Attack simulation request validation"""
    type: str = Field(..., description="Simulation type")
    file_path: Optional[str] = None
    
    @field_validator('type')
    @classmethod
    def validate_type(cls, v: str) -> str:
        allowed_types = ['phishing', 'ransomware', 'malware', 'network', 'file']
        if v not in allowed_types:
            raise ValueError(f'Type must be one of: {", ".join(allowed_types)}')
        return v
    
    @field_validator('file_path')
    @classmethod
    def sanitize_file_path(cls, v: Optional[str]) -> Optional[str]:
        if v is not None:
            # Basic path sanitization - remove potential path traversal
            v = v.replace('..', '').replace('~', '')
        return v


class CrossDeviceRequestSchema(BaseModel):
    """Cross-device request validation"""
    action: str = Field(..., description="Action to perform")
    device_id: Optional[str] = None
    
    @field_validator('action')
    @classmethod
    def validate_action(cls, v: str) -> str:
        allowed_actions = ['connect', 'disconnect', 'sync', 'immunize']
        if v not in allowed_actions:
            raise ValueError(f'Action must be one of: {", ".join(allowed_actions)}')
        return v


class AutopilotToggleSchema(BaseModel):
    """Autopilot mode toggle validation"""
    enabled: bool = Field(..., description="Enable or disable autopilot")
    
    @field_validator('enabled')
    @classmethod
    def validate_enabled(cls, v: bool) -> bool:
        return v


class TokenRefreshSchema(BaseModel):
    """Token refresh validation"""
    refresh_token: str = Field(..., description="Refresh token")
    
    @field_validator('refresh_token')
    @classmethod
    def validate_token(cls, v: str) -> str:
        if not v or len(v) < 20:
            raise ValueError('Invalid refresh token')
        return v

