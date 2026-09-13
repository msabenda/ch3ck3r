"""Alerting service — wraps the alert manager for use in the application."""

import logging

from app.alerting.manager import alert_manager, AlertPayload
from app.core.config import get_settings
from app.models import Scan, ScanStatus, Severity, Finding

logger = logging.getLogger(__name__)
settings = get_settings()


async def alert_scan_completed(scan: Scan, findings: list[Finding], project_name: str | None = None):
    """Send alerts when a scan completes with findings."""
    try:
        if scan.status == ScanStatus.COMPLETED and scan.total_findings > 0:
            await alert_manager.send_scan_completed_alert(scan, project_name)

            # Send critical finding alerts separately
            critical = [f for f in findings if f.severity in (Severity.CRITICAL, Severity.HIGH)]
            if critical:
                await alert_manager.send_critical_finding_alert(scan, findings, project_name)

        elif scan.status == ScanStatus.FAILED:
            await alert_manager.send_scan_failed_alert(
                scan, scan.error_message or "Unknown error", project_name
            )
    except Exception as e:
        logger.error(f"Failed to send scan alerts: {e}")


async def alert_critical_finding(scan: Scan, finding: Finding, project_name: str | None = None):
    """Alert on individual critical/high findings (for real-time)."""
    if finding.severity not in (Severity.CRITICAL, Severity.HIGH):
        return
    try:
        payload = AlertPayload(
            event="critical_finding",
            scan_id=str(scan.id),
            scan_type=scan.scan_type,
            target=scan.target,
            risk_score=scan.risk_score,
            total_findings=1,
            critical_count=1 if finding.severity == Severity.CRITICAL else 0,
            high_count=1 if finding.severity == Severity.HIGH else 0,
            medium_count=0,
            low_count=0,
            project_name=project_name,
            findings_summary=[
                {
                    "title": finding.title,
                    "severity": finding.severity.value,
                    "category": finding.category,
                    "endpoint": finding.endpoint,
                }
            ],
        )
        await alert_manager._dispatch(payload)
    except Exception as e:
        logger.error(f"Failed to send critical finding alert: {e}")
