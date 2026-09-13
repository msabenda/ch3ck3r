from pydantic_settings import BaseSettings, SettingsConfigDict
from functools import lru_cache
import os
from typing import Optional


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # Application
    APP_NAME: str = "Ch3ck3r"
    APP_VERSION: str = "0.1.0"
    DEBUG: bool = False
    SECRET_KEY: str = "change-me-in-production"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30

    # Database
    DATABASE_URL: str = "postgresql+asyncpg://ch3ck3r:ch3ck3r@localhost:5432/ch3ck3r"

    # Redis
    REDIS_URL: str = "redis://localhost:6379/0"

    # Celery
    CELERY_BROKER_URL: str = "redis://localhost:6379/1"
    CELERY_RESULT_BACKEND: str = "redis://localhost:6379/2"

    # Scanner
    SCAN_TIMEOUT_SECONDS: int = 300
    MAX_CONCURRENT_SCANS: int = 5
    SCAN_RESULT_RETENTION_DAYS: int = 90

    # External tools
    ZAP_PATH: Optional[str] = None
    NUCLEI_PATH: Optional[str] = None
    SEMGREP_PATH: Optional[str] = None

    # CORS
    CORS_ORIGINS: str = "http://localhost:3000,http://localhost:8000"

    # Logging
    LOG_LEVEL: str = "INFO"
    JSON_LOGS: bool = False

    # Rate limiting
    RATE_LIMIT_ENABLED: bool = True
    RATE_LIMIT_REQUESTS: int = 100
    RATE_LIMIT_WINDOW_SECONDS: int = 60

    # Webhook broker
    WEBHOOK_ENABLED: bool = False

    # Multi-tenancy
    MULTI_TENANT_ENABLED: bool = False

    @property
    def cors_origins_list(self) -> list[str]:
        return [o.strip() for o in self.CORS_ORIGINS.split(",") if o.strip()]

    @property
    def database_url_sync(self) -> str:
        """Return sync DB URL for Alembic (asyncpg → psycopg2)"""
        return self.DATABASE_URL.replace("+asyncpg", "")


@lru_cache()
def get_settings() -> Settings:
    return Settings()
