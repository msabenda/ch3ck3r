from pydantic import BaseModel, EmailStr, Field
from typing import Optional
from datetime import datetime


# ─── Auth ────────────────────────────────────────────────────────
class TokenPayload(BaseModel):
    sub: str
    role: str
    exp: Optional[int] = None


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"


class LoginRequest(BaseModel):
    email: EmailStr
    password: str = Field(..., min_length=8)


# ─── User ────────────────────────────────────────────────────────
class UserCreate(BaseModel):
    email: EmailStr
    password: str = Field(..., min_length=8)
    full_name: str = Field(..., min_length=1, max_length=255)
    role: str = "viewer"


class UserResponse(BaseModel):
    id: str
    email: str
    full_name: str
    role: str
    is_active: bool
    created_at: datetime

    model_config = {"from_attributes": True}


class UserUpdate(BaseModel):
    full_name: Optional[str] = None
    role: Optional[str] = None
    is_active: Optional[bool] = None


# ─── Project ─────────────────────────────────────────────────────
class ProjectCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=255)
    description: Optional[str] = None
    repository_url: Optional[str] = None


class ProjectUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    repository_url: Optional[str] = None


class ProjectResponse(BaseModel):
    id: str
    name: str
    description: Optional[str]
    repository_url: Optional[str]
    user_id: str
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


# ─── Scan ────────────────────────────────────────────────────────
class ScanCreate(BaseModel):
    project_id: str
    scan_type: str = Field(..., pattern=r"^(openapi|zap|nuclei|semgrep|full)$")
    target: str = Field(..., min_length=1)


class ScanResponse(BaseModel):
    id: str
    project_id: str
    user_id: str
    scan_type: str
    target: str
    status: str
    risk_score: Optional[float]
    total_findings: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    info_count: int
    started_at: Optional[datetime]
    completed_at: Optional[datetime]
    error_message: Optional[str]
    created_at: datetime

    model_config = {"from_attributes": True}


# ─── Finding ─────────────────────────────────────────────────────
class FindingResponse(BaseModel):
    id: str
    scan_id: str
    title: str
    description: Optional[str]
    severity: str
    category: str
    owasp_category: Optional[str]
    endpoint: Optional[str]
    evidence: Optional[dict]
    remediation: Optional[str]
    cve_id: Optional[str]
    cwe_id: Optional[int]
    false_positive: bool
    created_at: datetime

    model_config = {"from_attributes": True}


class FindingUpdate(BaseModel):
    false_positive: Optional[bool] = None


# ─── Report ──────────────────────────────────────────────────────
class ReportResponse(BaseModel):
    id: str
    scan_id: str
    project_id: str
    format: str
    summary: Optional[dict]
    file_path: Optional[str]
    created_at: datetime

    model_config = {"from_attributes": True}


# ─── Generic ─────────────────────────────────────────────────────
class PaginatedResponse(BaseModel):
    items: list
    total: int
    page: int
    page_size: int
    total_pages: int


class MessageResponse(BaseModel):
    message: str
    detail: Optional[str] = None


class HealthResponse(BaseModel):
    status: str
    version: str
    database: str
    redis: str
