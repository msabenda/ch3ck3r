"""Scan diffing — compare two scans to track vulnerability changes over time."""

import logging
from dataclasses import dataclass, field
from typing import Optional
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import Scan, Finding, Severity

logger = logging.getLogger(__name__)


@dataclass
class DiffEntry:
    """A single change between two scans."""
    type: str  # "new", "fixed", "recurring", "severity_changed"
    title: str
    old_severity: Optional[str] = None
    new_severity: Optional[str] = None
    old_category: Optional[str] = None
    new_category: Optional[str] = None
    endpoint: Optional[str] = None
    cve_id: Optional[str] = None
    finding_id: Optional[str] = None


@dataclass
class ScanDiff:
    """Full diff between two scans."""
    base_scan_id: str
    compare_scan_id: str
    target: str
    new_findings: list[DiffEntry] = field(default_factory=list)
    fixed_findings: list[DiffEntry] = field(default_factory=list)
    recurring_findings: list[DiffEntry] = field(default_factory=list)
    severity_changes: list[DiffEntry] = field(default_factory=list)
    risk_score_change: Optional[float] = None

    @property
    def total_changes(self) -> int:
        return len(self.new_findings) + len(self.fixed_findings) + \
               len(self.recurring_findings) + len(self.severity_changes)

    @property
    def net_risk_change(self) -> str:
        if self.risk_score_change is None:
            return "unknown"
        if self.risk_score_change > 0:
            return f"+{self.risk_score_change:.1f} (worse)"
        elif self.risk_score_change < 0:
            return f"{self.risk_score_change:.1f} (improved)"
        return "0.0 (unchanged)"


class ScanDiffEngine:
    """Compares findings between two scans to identify changes."""

    def __init__(self, db: AsyncSession):
        self.db = db

    async def diff(self, base_scan_id: UUID, compare_scan_id: UUID) -> Optional[ScanDiff]:
        """Produce a diff between two scans."""
        base_scan = await self._get_scan(base_scan_id)
        compare_scan = await self._get_scan(compare_scan_id)
        if not base_scan or not compare_scan:
            return None

        base_findings = await self._get_findings(base_scan_id)
        compare_findings = await self._get_findings(compare_scan_id)

        # Index findings by fingerprint (title + endpoint for matching)
        def fingerprint(f: Finding) -> str:
            return f"{f.title}|{f.endpoint or ''}|{f.cve_id or ''}"

        base_map = {fingerprint(f): f for f in base_findings}
        compare_map = {fingerprint(f): f for f in compare_findings}

        base_keys = set(base_map.keys())
        compare_keys = set(compare_map.keys())

        new_keys = compare_keys - base_keys
        fixed_keys = base_keys - compare_keys
        common_keys = base_keys & compare_keys

        diff = ScanDiff(
            base_scan_id=str(base_scan_id),
            compare_scan_id=str(compare_scan_id),
            target=compare_scan.target,
        )

        # New findings
        for key in new_keys:
            f = compare_map[key]
            diff.new_findings.append(DiffEntry(
                type="new",
                title=f.title,
                new_severity=f.severity.value,
                new_category=f.category,
                endpoint=f.endpoint,
                cve_id=f.cve_id,
                finding_id=str(f.id),
            ))

        # Fixed findings
        for key in fixed_keys:
            f = base_map[key]
            diff.fixed_findings.append(DiffEntry(
                type="fixed",
                title=f.title,
                old_severity=f.severity.value,
                old_category=f.category,
                endpoint=f.endpoint,
                cve_id=f.cve_id,
            ))

        # Severity changes
        for key in common_keys:
            base_f = base_map[key]
            comp_f = compare_map[key]
            if base_f.severity != comp_f.severity:
                diff.severity_changes.append(DiffEntry(
                    type="severity_changed",
                    title=comp_f.title,
                    old_severity=base_f.severity.value,
                    new_severity=comp_f.severity.value,
                    endpoint=comp_f.endpoint,
                    cve_id=comp_f.cve_id,
                    finding_id=str(comp_f.id),
                ))

        # Recurring severity
        for key in common_keys:
            f = compare_map[key]
            if fingerprint(f) not in fixed_keys:
                diff.recurring_findings.append(DiffEntry(
                    type="recurring",
                    title=f.title,
                    new_severity=f.severity.value,
                    endpoint=f.endpoint,
                    cve_id=f.cve_id,
                ))

        # Risk score change
        if base_scan.risk_score is not None and compare_scan.risk_score is not None:
            diff.risk_score_change = round(compare_scan.risk_score - base_scan.risk_score, 2)

        return diff

    async def diff_latest(self, project_id: UUID, scan_type: str) -> Optional[ScanDiff]:
        """Compare the latest two scans of the same type in a project."""
        result = await self.db.execute(
            select(Scan)
            .where(Scan.project_id == project_id, Scan.scan_type == scan_type)
            .where(Scan.status == "completed")
            .order_by(Scan.created_at.desc())
            .limit(2)
        )
        scans = result.scalars().all()
        if len(scans) < 2:
            return None
        return await self.diff(scans[1].id, scans[0].id)

    async def _get_scan(self, scan_id: UUID) -> Optional[Scan]:
        result = await self.db.execute(select(Scan).where(Scan.id == scan_id))
        return result.scalar_one_or_none()

    async def _get_findings(self, scan_id: UUID) -> list[Finding]:
        result = await self.db.execute(
            select(Finding).where(Finding.scan_id == scan_id)
        )
        return list(result.scalars().all())
