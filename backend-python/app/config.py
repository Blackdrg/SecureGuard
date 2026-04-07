"""
Application Configuration
Manages environment variables and settings
"""

from pydantic_settings import BaseSettings
from typing import List


class Settings(BaseSettings):
    """Application settings from environment variables"""

    # Application
    APP_NAME: str = "SecureGuard API"
    VERSION: str = "2.0.0"
    DEBUG: bool = False
    PORT: int = 8000

    # Database
    DATABASE_URL: str = "postgresql://secureguard:secure@localhost:5432/secureguard"

    # Redis
    REDIS_URL: str = "redis://localhost:6379"

    # JWT Authentication
    JWT_SECRET_KEY: str = "your-secret-key-change-in-production"
    JWT_ALGORITHM: str = "HS256"
    JWT_ACCESS_TOKEN_EXPIRE_MINUTES: int = 60
    JWT_REFRESH_TOKEN_EXPIRE_DAYS: int = 7

    # Security
    CORS_ORIGINS: List[str] = ["http://localhost:3000", "http://localhost:8765"]
    RATE_LIMIT_PER_MINUTE: int = 60

    # ML Service
    ML_MODEL_PATH: str = "./ml_models/threat_model.joblib"
    ML_THRESHOLD: float = 0.7

    # External Services (for threat intelligence)
    VIRUSTOTAL_API_KEY: str = ""

    class Config:
        env_file = ".env"
        case_sensitive = True


settings = Settings()

