"""Scanner service — orchestrates scan lifecycle with alerting and multi-scanner support."""

import logging
import asyncio
from datetime import datetime, timezone
from typing import Optional
from uuid import UUID

from sqlalchemy import select, func, case
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import Scan, ScanStatus, Finding, Severity
from app.schemas import ScanCreate
from app.scanner.plugins import get_scanner, get_available_scanners, run_full_scan
from app.alerting import alert_scan_completed
from app.api.v1.ws import progress_manager
from app.events import publish_webhook_event

logger = logging.getLogger(__name__)


class ScanOrchestrator:
    """Handles scan creation, execution, and result persistence."""

    def __init__(self, db: AsyncSession):
        self.db = db

    async def create_scan(self, scan_data: ScanCreate, user_id: UUID) -> Scan:
        """Create a new scan record."""
        scanner = get_scanner(scan_data.scan_type)
        if not scanner:
            raise ValueError(f"Unknown scanner type: {scan_data.scan_type}")

        valid = await scanner.validate_target(scan_data.target)
        if not valid:
            raise ValueError(f"Invalid target for scanner {scan_data.scan_type}: {scan_data.target}")

        scan = Scan(
            project_id=UUID(scan_data.project_id),
            user_id=user_id,
            scan_type=scan_data.scan_type,
            target=scan_data.target,
            status=ScanStatus.PENDING,
        )
        self.db.add(scan)
        await self.db.flush()
        await self.db.refresh(scan)
        return scan

    # ── Single Scanner Execution ────────────────────────────────

    async def execute_scan(self, scan_id: UUID) -> Scan:
        """Execute a single scanner and persist results."""
        result = await self.db.execute(select(Scan).where(Scan.id == scan_id))
        scan = result.scalar_one_or_none()
        if not scan:
            raise ValueError(f"Scan not found: {scan_id}")

        scanner = get_scanner(scan.scan_type)
        if not scanner:
            scan.status = ScanStatus.FAILED
            scan.error_message = f"Unknown scanner: {scan.scan_type}"
            await self.db.flush()
            return scan

        scan.status = ScanStatus.RUNNING
        scan.started_at = datetime.now(timezone.utc)
        await self.db.flush()
        await progress_manager.broadcast_scan_event(scan, "scan_started")
        await publish_webhook_event(
            "scan.started", str(scan.id), str(scan.project_id),
            {"scan_type": scan.scan_type, "target": scan.target},
        )

        try:
            scan_result = await scanner.scan(scan.target)
            await self._persist_results(scan, scan_result)
            await progress_manager.broadcast_scan_event(scan, "scan_completed")
            await publish_webhook_event(
                "scan.completed", str(scan.id), str(scan.project_id),
                {
                    "scan_type": scan.scan_type,
                    "target": scan.target,
                    "risk_score": scan.risk_score,
                    "total_findings": scan.total_findings,
                },
            )

        except Exception as e:
            scan.status = ScanStatus.FAILED
            scan.error_message = str(e)
            scan.completed_at = datetime.now(timezone.utc)
            logger.exception(f"Scan {scan_id} failed: {e}")

        await self.db.flush()
        await progress_manager.broadcast_scan_event(scan, f"scan_{scan.status.value}")
        await publish_webhook_event(
            f"scan.{scan.status.value}", str(scan.id), str(scan.project_id),
            {
                "scan_type": scan.scan_type,
                "target": scan.target,
                "risk_score": scan.risk_score,
                "error": scan.error_message,
            },
        )

        # Fire alerts (non-blocking)
        try:
            findings = await self._get_findings(scan.id)
            await alert_scan_completed(scan, findings)
        except Exception as e:
            logger.warning(f"Alert dispatch failed: {e}")

        return scan

    # ── Full Scan: runs ALL applicable scanners ──────────────────

    async def execute_full_scan(
        self,
        target: str,
        user_id: UUID,
        project_id: UUID,
        repo_url: Optional[str] = None,
    ) -> dict[str, UUID]:
        """Run all available scanners against a target.

        Creates individual Scan records per scanner and returns {scanner_name: scan_id}.
        """
        scan_ids = {}
        scanners = get_available_scanners()

        for scanner_name in scanners:
            scanner = get_scanner(scanner_name)
            if not scanner:
                continue

            scan_target = repo_url if repo_url and scanner_name == "semgrep" else target

            valid = await scanner.validate_target(scan_target)
            if not valid:
                continue

            scan = Scan(
                project_id=project_id,
                user_id=user_id,
                scan_type=scanner_name,
                target=scan_target,
                status=ScanStatus.PENDING,
            )
            self.db.add(scan)
            await self.db.flush()
            await self.db.refresh(scan)
            scan_ids[scanner_name] = scan.id

        # Execute each scan
        for scanner_name, scan_id in scan_ids.items():
            try:
                await self.execute_scan(scan_id)
            except Exception as e:
                logger.error(f"Full scan sub-scan {scanner_name} failed: {e}")

        return scan_ids

    async def _persist_results(self, scan: Scan, scan_result):
        """Persist scanner results to the database."""
        from app.metrics import scans_total, scans_duration_seconds, active_scans, findings_total, risk_score_gauge

        scan.status = ScanStatus(scan_result.status)
        scan.risk_score = scan_result.risk_score
        scan.completed_at = datetime.now(timezone.utc)

        if scan_result.error_message:
            scan.error_message = scan_result.error_message

        # Track scan duration
        if scan.started_at and scan.completed_at:
            duration = (scan.completed_at - scan.started_at).total_seconds()
            scans_duration_seconds.labels(scan_type=scan.scan_type).observe(duration)

        # Update Prometheus counters
        scans_total.labels(scan_type=scan.scan_type, status=scan.status.value).inc()
        if scan.risk_score is not None:
            risk_score_gauge.labels(scan_type=scan.scan_type).set(scan.risk_score)

        # Persist findings
        for finding_data in scan_result.findings:
            finding = Finding(
                scan_id=scan.id,
                title=finding_data.title,
                description=finding_data.description,
                severity=Severity(finding_data.severity),
                category=finding_data.category,
                owasp_category=finding_data.owasp_category,
                endpoint=finding_data.endpoint,
                evidence=finding_data.evidence,
                remediation=finding_data.remediation,
                cve_id=finding_data.cve_id,
                cwe_id=finding_data.cwe_id,
            )
            self.db.add(finding)

            # Track finding counts per severity/category
            findings_total.labels(
                severity=finding_data.severity,
                category=finding_data.category,
            ).inc()

            # Broadcast finding in real-time
            self._safe_broadcast_finding(scan, finding_data)

        await self.db.flush()

        # Update counts
        await self._update_counts(scan)

    async def _get_findings(self, scan_id: UUID) -> list[Finding]:
        """Get all findings for a scan."""
        result = await self.db.execute(
            select(Finding).where(Finding.scan_id == scan_id)
        )
        return list(result.scalars().all())

    async def _update_counts(self, scan: Scan):
        """Recalculate finding counts for a scan."""
        count_result = await self.db.execute(
            select(
                func.count().label("total"),
                func.sum(case((Finding.severity == Severity.CRITICAL, 1), else_=0)).label("critical"),
                func.sum(case((Finding.severity == Severity.HIGH, 1), else_=0)).label("high"),
                func.sum(case((Finding.severity == Severity.MEDIUM, 1), else_=0)).label("medium"),
                func.sum(case((Finding.severity == Severity.LOW, 1), else_=0)).label("low"),
                func.sum(case((Finding.severity == Severity.INFO, 1), else_=0)).label("info"),
            ).where(Finding.scan_id == scan.id)
        )
        row = count_result.one()
        scan.total_findings = row.total or 0
        scan.critical_count = row.critical or 0
        scan.high_count = row.high or 0
        scan.medium_count = row.medium or 0
        scan.low_count = row.low or 0
        scan.info_count = row.info or 0

    def _safe_broadcast_finding(self, scan: Scan, finding_data):
        """Broadcast finding via WebSocket (non-blocking)."""
        try:
            asyncio.ensure_future(
                progress_manager.broadcast_finding(
                    str(scan.id),
                    finding={
                        "title": finding_data.title,
                        "severity": finding_data.severity,
                        "category": finding_data.category,
                        "endpoint": finding_data.endpoint,
                        "owasp_category": finding_data.owasp_category,
                    }
                )
            )
        except Exception:
            pass

    # ── Stats ────────────────────────────────────────────────────

    async def get_scan_stats(self, user_id: Optional[UUID] = None) -> dict:
        """Get aggregate scan statistics."""
        query = select(Scan)
        if user_id:
            query = query.where(Scan.user_id == user_id)

        result = await self.db.execute(query)
        scans = list(result.scalars().all())

        total = len(scans)
        completed = sum(1 for s in scans if s.status == ScanStatus.COMPLETED)
        failed = sum(1 for s in scans if s.status == ScanStatus.FAILED)
        running = sum(1 for s in scans if s.status == ScanStatus.RUNNING)

        total_critical = sum(s.critical_count or 0 for s in scans)

        # Average risk score (most recent 10 scans)
        recent = sorted(scans, key=lambda s: s.created_at or datetime.min, reverse=True)[:10]
        risk_scores = [s.risk_score for s in recent if s.risk_score is not None]
        avg_risk = sum(risk_scores) / len(risk_scores) if risk_scores else 0

        return {
            "total_scans": total,
            "completed_scans": completed,
            "failed_scans": failed,
            "running_scans": running,
            "total_findings": sum(s.total_findings or 0 for s in scans),
            "critical_findings": total_critical,
            "average_risk_score": round(avg_risk, 2),
        }
