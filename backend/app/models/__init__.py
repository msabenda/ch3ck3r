import enum
import uuid
from datetime import datetime, timezone
from sqlalchemy import (
    Column, String, Text, Boolean, DateTime, ForeignKey,
    Enum, Integer, JSON, Float, Index
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship
from app.db.session import Base


class UserRole(str, enum.Enum):
    ADMIN = "admin"
    SCANNER = "scanner"
    VIEWER = "viewer"


def utcnow():
    return datetime.now(timezone.utc)


class User(Base):
    __tablename__ = "users"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    email = Column(String(255), unique=True, nullable=False, index=True)
    hashed_password = Column(String(255), nullable=False)
    full_name = Column(String(255), nullable=False)
    role = Column(Enum(UserRole), default=UserRole.VIEWER, nullable=False)
    is_active = Column(Boolean, default=True)
    api_key = Column(String(128), unique=True, index=True)
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)
    updated_at = Column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)

    scans = relationship("Scan", back_populates="user", lazy="selectin")

    __table_args__ = {"extend_existing": True}


class Project(Base):
    __tablename__ = "projects"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name = Column(String(255), nullable=False)
    description = Column(Text)
    repository_url = Column(String(500))
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=False)
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)
    updated_at = Column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)

    scans = relationship("Scan", back_populates="project", lazy="selectin")

    __table_args__ = (
        Index("idx_project_user", "user_id"),
        {"extend_existing": True},
    )


class ScanStatus(str, enum.Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class Scan(Base):
    __tablename__ = "scans"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    project_id = Column(UUID(as_uuid=True), ForeignKey("projects.id"), nullable=False)
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=False)
    scan_type = Column(String(50), nullable=False)  # openapi, zap, nuclei, semgrep, full
    target = Column(Text, nullable=False)  # URL or file path
    status = Column(Enum(ScanStatus), default=ScanStatus.PENDING, nullable=False)
    risk_score = Column(Float)  # 0.0 - 10.0
    total_findings = Column(Integer, default=0)
    critical_count = Column(Integer, default=0)
    high_count = Column(Integer, default=0)
    medium_count = Column(Integer, default=0)
    low_count = Column(Integer, default=0)
    info_count = Column(Integer, default=0)
    started_at = Column(DateTime(timezone=True))
    completed_at = Column(DateTime(timezone=True))
    error_message = Column(Text)
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)

    user = relationship("User", back_populates="scans", lazy="selectin")
    project = relationship("Project", back_populates="scans", lazy="selectin")
    findings = relationship("Finding", back_populates="scan", lazy="selectin", cascade="all, delete-orphan")

    __table_args__ = (
        Index("idx_scan_project", "project_id"),
        Index("idx_scan_status", "status"),
        Index("idx_scan_user", "user_id"),
        {"extend_existing": True},
    )


class Severity(str, enum.Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Finding(Base):
    __tablename__ = "findings"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    scan_id = Column(UUID(as_uuid=True), ForeignKey("scans.id"), nullable=False)
    title = Column(String(500), nullable=False)
    description = Column(Text)
    severity = Column(Enum(Severity), nullable=False)
    category = Column(String(100), nullable=False)  # auth, cors, rate_limiting, etc.
    owasp_category = Column(String(100))  # API1:2019, etc.
    endpoint = Column(String(500))  # affected API endpoint
    evidence = Column(JSON)  # raw evidence from scanner
    remediation = Column(Text)
    cve_id = Column(String(50))
    cwe_id = Column(Integer)
    false_positive = Column(Boolean, default=False)
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)

    scan = relationship("Scan", back_populates="findings", lazy="selectin")

    __table_args__ = (
        Index("idx_finding_scan", "scan_id"),
        Index("idx_finding_severity", "severity"),
        Index("idx_finding_category", "category"),
        {"extend_existing": True},
    )


class Report(Base):
    __tablename__ = "reports"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    scan_id = Column(UUID(as_uuid=True), ForeignKey("scans.id"), nullable=False)
    project_id = Column(UUID(as_uuid=True), ForeignKey("projects.id"), nullable=False)
    format = Column(String(20), nullable=False, default="pdf")  # pdf, html, json, sarif
    summary = Column(JSON)
    file_path = Column(String(500))
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)

    __table_args__ = (
        Index("idx_report_scan", "scan_id"),
        {"extend_existing": True},
    )
