"""Alerting system — sends notifications via webhooks, Slack, email, etc."""

import asyncio
import json
import logging
from dataclasses import dataclass, field
from typing import Optional

import httpx

from app.models import Scan, Severity

logger = logging.getLogger(__name__)


@dataclass
class AlertPayload:
    """Standardized alert payload sent to notification channels."""
    event: str  # scan_completed, critical_finding, scan_failed
    scan_id: str
    scan_type: str
    target: str
    risk_score: Optional[float]
    total_findings: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    project_name: Optional[str] = None
    findings_summary: Optional[list[dict]] = None
    report_url: Optional[str] = None


class AlertManager:
    """Manages sending alerts to configured channels."""

    def __init__(self):
        self.webhook_urls: list[str] = []
        self.slack_webhook_url: Optional[str] = None
        self.discord_webhook_url: Optional[str] = None
        self.email_config: Optional[dict] = None
        self._load_config()

    def _load_config(self):
        """Load alerting config from environment variables."""
        import os

        # Slack
        self.slack_webhook_url = os.environ.get("SLACK_WEBHOOK_URL")

        # Discord
        self.discord_webhook_url = os.environ.get("DISCORD_WEBHOOK_URL")

        # Generic webhooks
        webhooks = os.environ.get("ALERT_WEBHOOK_URLS", "")
        if webhooks:
            self.webhook_urls = [u.strip() for u in webhooks.split(",") if u.strip()]

        # Email (SMTP)
        if os.environ.get("SMTP_HOST"):
            self.email_config = {
                "host": os.environ["SMTP_HOST"],
                "port": int(os.environ.get("SMTP_PORT", "587")),
                "username": os.environ.get("SMTP_USERNAME", ""),
                "password": os.environ.get("SMTP_PASSWORD", ""),
                "from": os.environ.get("SMTP_FROM", "ch3ck3r@localhost"),
                "to": os.environ.get("ALERT_EMAIL_TO", ""),
                "use_tls": os.environ.get("SMTP_USE_TLS", "true").lower() == "true",
            }

    async def send_scan_completed_alert(self, scan: Scan, project_name: Optional[str] = None):
        """Send alert when a scan completes."""
        if scan.total_findings == 0:
            return  # Don't spam on clean scans

        payload = AlertPayload(
            event="scan_completed",
            scan_id=str(scan.id),
            scan_type=scan.scan_type,
            target=scan.target,
            risk_score=scan.risk_score,
            total_findings=scan.total_findings,
            critical_count=scan.critical_count,
            high_count=scan.high_count,
            medium_count=scan.medium_count,
            low_count=scan.low_count,
            project_name=project_name,
        )
        await self._dispatch(payload)

    async def send_critical_finding_alert(
        self, scan: Scan, findings: list, project_name: Optional[str] = None
    ):
        """Alert on critical/high severity findings immediately."""
        critical = [f for f in findings if f.severity in (Severity.CRITICAL, Severity.HIGH)]
        if not critical:
            return

        payload = AlertPayload(
            event="critical_finding",
            scan_id=str(scan.id),
            scan_type=scan.scan_type,
            target=scan.target,
            risk_score=scan.risk_score,
            total_findings=len(critical),
            critical_count=scan.critical_count,
            high_count=scan.high_count,
            medium_count=0,
            low_count=0,
            project_name=project_name,
            findings_summary=[
                {
                    "title": f.title,
                    "severity": f.severity.value,
                    "category": f.category,
                    "endpoint": f.endpoint,
                }
                for f in critical[:10]
            ],
        )
        await self._dispatch(payload)

    async def send_scan_failed_alert(self, scan: Scan, error: str, project_name: Optional[str] = None):
        """Alert when a scan fails."""
        payload = AlertPayload(
            event="scan_failed",
            scan_id=str(scan.id),
            scan_type=scan.scan_type,
            target=scan.target,
            risk_score=None,
            total_findings=0,
            critical_count=0,
            high_count=0,
            medium_count=0,
            low_count=0,
            project_name=project_name,
            findings_summary=[{"error": error}],
        )
        await self._dispatch(payload)

    async def _dispatch(self, payload: AlertPayload):
        """Send the alert to all configured channels."""
        tasks = []

        if self.slack_webhook_url:
            tasks.append(self._send_slack(payload))
        if self.discord_webhook_url:
            tasks.append(self._send_discord(payload))
        for url in self.webhook_urls:
            tasks.append(self._send_webhook(payload, url))
        if self.email_config:
            tasks.append(self._send_email(payload))

        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

    async def _send_slack(self, payload: AlertPayload):
        """Send a Slack webhook message."""
        color_map = {
            "scan_completed": "#22c55e",
            "critical_finding": "#ef4444",
            "scan_failed": "#f97316",
        }
        color = color_map.get(payload.event, "#6b7280")

        blocks = [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": f"🔍 Ch3ck3r: {payload.event.replace('_', ' ').title()}",
                },
            },
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*Target:*\n{payload.target}"},
                    {"type": "mrkdwn", "text": f"*Type:*\n{payload.scan_type}"},
                ],
            },
        ]

        if payload.risk_score is not None:
            blocks.append({
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*Risk Score:*\n{payload.risk_score:.1f}/10"},
                    {"type": "mrkdwn", "text": f"*Findings:*\n{payload.total_findings}"},
                ],
            })

        if payload.critical_count > 0:
            blocks.append({
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"⚠️ *{payload.critical_count} critical* / *{payload.high_count} high* severity findings",
                },
            })

        if payload.project_name:
            blocks.insert(1, {
                "type": "section",
                "text": {"type": "mrkdwn", "text": f"*Project:* {payload.project_name}"},
            })

        if payload.findings_summary:
            summary_text = "\n".join(
                f"• `{f['severity'].upper()}` {f['title']}" + (f" — {f['endpoint'][:60]}" if f.get('endpoint') else "")
                for f in payload.findings_summary[:5]
            )
            blocks.append({
                "type": "section",
                "text": {"type": "mrkdwn", "text": f"*Top Findings:*\n{summary_text}"},
            })

        blocks.append({
            "type": "actions",
            "elements": [
                {
                    "type": "button",
                    "text": {"type": "plain_text", "text": "View in Ch3ck3r"},
                    "url": f"{os.environ.get('CH3CK3R_URL', 'http://localhost:3000')}/scans/{payload.scan_id}",
                }
            ],
        })

        try:
            async with httpx.AsyncClient(timeout=10) as client:
                r = await client.post(self.slack_webhook_url, json={"attachments": [{"color": color, "blocks": blocks}]})
                if r.status_code not in (200, 204):
                    logger.warning(f"Slack webhook returned {r.status_code}")
        except Exception as e:
            logger.error(f"Failed to send Slack alert: {e}")

    async def _send_discord(self, payload: AlertPayload):
        """Send a Discord webhook message."""
        color_map = {
            "scan_completed": 5763719,
            "critical_finding": 15548997,
            "scan_failed": 15105570,
        }
        color = color_map.get(payload.event, 10070709)

        embed = {
            "title": f"🔍 Ch3ck3r: {payload.event.replace('_', ' ').title()}",
            "color": color,
            "fields": [
                {"name": "Target", "value": payload.target, "inline": True},
                {"name": "Type", "value": payload.scan_type, "inline": True},
            ],
            "timestamp": __import__("datetime").datetime.now().isoformat(),
        }

        if payload.risk_score is not None:
            embed["fields"].append({"name": "Risk Score", "value": f"{payload.risk_score:.1f}/10", "inline": True})
            embed["fields"].append({"name": "Findings", "value": str(payload.total_findings), "inline": True})

        if payload.critical_count > 0:
            embed["fields"].append({
                "name": "Critical Findings",
                "value": f"⚠️ {payload.critical_count} critical, {payload.high_count} high",
                "inline": False,
            })

        if payload.project_name:
            embed["fields"].insert(0, {"name": "Project", "value": payload.project_name, "inline": False})

        if payload.findings_summary:
            summary = "\n".join(f"`{f['severity'].upper()}` {f['title']}" for f in payload.findings_summary[:5])
            embed["fields"].append({"name": "Top Findings", "value": summary[:1024], "inline": False})

        try:
            async with httpx.AsyncClient(timeout=10) as client:
                r = await client.post(self.discord_webhook_url, json={"embeds": [embed]})
                if r.status_code not in (200, 204):
                    logger.warning(f"Discord webhook returned {r.status_code}")
        except Exception as e:
            logger.error(f"Failed to send Discord alert: {e}")

    async def _send_webhook(self, payload: AlertPayload, url: str):
        """Send a generic JSON webhook."""
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                r = await client.post(
                    url,
                    json={
                        "event": payload.event,
                        "scan_id": payload.scan_id,
                        "target": payload.target,
                        "scan_type": payload.scan_type,
                        "risk_score": payload.risk_score,
                        "findings_count": payload.total_findings,
                        "severity_breakdown": {
                            "critical": payload.critical_count,
                            "high": payload.high_count,
                            "medium": payload.medium_count,
                            "low": payload.low_count,
                        },
                        "findings_summary": payload.findings_summary,
                        "project_name": payload.project_name,
                        "timestamp": __import__("datetime").datetime.now().isoformat(),
                    },
                )
                if r.status_code not in (200, 204):
                    logger.warning(f"Webhook {url} returned {r.status_code}")
        except Exception as e:
            logger.error(f"Failed to send webhook to {url}: {e}")

    async def _send_email(self, payload: AlertPayload):
        """Send email notification via SMTP."""
        # Email sending via SMTP
        email_config = self.email_config
        if not email_config or not email_config.get("to"):
            return

        try:
            import smtplib
            from email.mime.text import MIMEText
            from email.mime.multipart import MIMEMultipart

            subject = f"[Ch3ck3r] {payload.event.replace('_', ' ').title()} — {payload.target[:80]}"

            body = f"""
Ch3ck3r Alert: {payload.event.replace('_', ' ').title()}

Target: {payload.target}
Scan Type: {payload.scan_type}
Risk Score: {'{:.1f}'.format(payload.risk_score) + '/10' if payload.risk_score else 'N/A'}
Total Findings: {payload.total_findings}
  Critical: {payload.critical_count}
  High: {payload.high_count}
  Medium: {payload.medium_count}
  Low: {payload.low_count}

Project: {payload.project_name or 'N/A'}

View in Ch3ck3r: {os.environ.get('CH3CK3R_URL', 'http://localhost:3000')}/scans/{payload.scan_id}
"""

            msg = MIMEMultipart()
            msg["From"] = email_config["from"]
            msg["To"] = email_config["to"]
            msg["Subject"] = subject
            msg.attach(MIMEText(body, "plain"))

            with smtplib.SMTP(email_config["host"], email_config["port"]) as server:
                if email_config.get("use_tls", True):
                    server.starttls()
                if email_config.get("username"):
                    server.login(email_config["username"], email_config["password"])
                server.send_message(msg)

            logger.info(f"Email alert sent to {email_config['to']}")

        except Exception as e:
            logger.error(f"Failed to send email alert: {e}")


# Global alert manager instance
alert_manager = AlertManager()
