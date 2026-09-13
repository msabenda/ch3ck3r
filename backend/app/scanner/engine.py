"""Scanner plugin architecture."""
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Optional
from datetime import datetime


@dataclass
class FindingResult:
    """Standardized finding from any scanner plugin."""
    title: str
    description: Optional[str] = None
    severity: str = "info"  # critical, high, medium, low, info
    category: str = "general"
    owasp_category: Optional[str] = None
    endpoint: Optional[str] = None
    evidence: Optional[dict] = None
    remediation: Optional[str] = None
    cve_id: Optional[str] = None
    cwe_id: Optional[int] = None


@dataclass
class ScanResult:
    """Standardized scan result from any plugin."""
    plugin_name: str
    target: str
    status: str = "completed"  # completed, failed, cancelled
    findings: list[FindingResult] = field(default_factory=list)
    risk_score: float = 0.0
    error_message: Optional[str] = None
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    raw_output: Optional[dict] = None


class BaseScanner(ABC):
    """Abstract base for all scanner plugins."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Unique plugin identifier."""
        ...

    @abstractmethod
    async def scan(self, target: str, **kwargs) -> ScanResult:
        """Execute a scan against the target."""
        ...

    @abstractmethod
    async def validate_target(self, target: str) -> bool:
        """Return True if the target is valid for this scanner."""
        ...

    def calculate_risk_score(self, findings: list[FindingResult]) -> float:
        """Calculate weighted risk score 0.0–10.0."""
        if not findings:
            return 0.0
        weights = {"critical": 10.0, "high": 7.5, "medium": 5.0, "low": 2.5, "info": 0.5}
        total = sum(weights.get(f.severity, 0) for f in findings)
        raw = total / (len(findings) or 1)
        return round(min(raw, 10.0), 1)
