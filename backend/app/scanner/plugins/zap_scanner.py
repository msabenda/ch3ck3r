"""OWASP ZAP scanner plugin — runs ZAP in daemon mode for active/passive scanning."""

import asyncio
import json
import logging
import os
import tempfile
from typing import Optional

import httpx

from app.scanner.engine import BaseScanner, ScanResult, FindingResult
from app.core.config import get_settings

logger = logging.getLogger(__name__)
settings = get_settings()


class ZAPScanner(BaseScanner):
    """Wrapper for OWASP ZAP API scanning.

    Requires ZAP running in daemon mode: zap.sh -daemon -port 8080 -config api.key=ch3ck3r
    or uses ZAP_PATH from config to start one automatically.
    """

    name = "zap"

    ZAP_API_KEY = "ch3ck3r"
    ZAP_HOST = "http://127.0.0.1:8080"

    async def validate_target(self, target: str) -> bool:
        return target.startswith(("http://", "https://"))

    async def _zap_api(self, endpoint: str, params: Optional[dict] = None) -> dict:
        """Call ZAP API."""
        p = params or {}
        p["apikey"] = self.ZAP_API_KEY
        try:
            async with httpx.AsyncClient(timeout=30) as client:
                r = await client.get(f"{self.ZAP_HOST}/JSON/{endpoint}", params=p)
                return r.json()
        except Exception as e:
            logger.warning(f"ZAP API call failed: {endpoint}: {e}")
            return {}

    async def _ensure_zap_running(self) -> bool:
        """Check if ZAP is running, optionally start it."""
        try:
            async with httpx.AsyncClient(timeout=5) as client:
                r = await client.get(
                    f"{self.ZAP_HOST}/JSON/core/view/version/",
                    params={"apikey": self.ZAP_API_KEY},
                )
                return r.status_code == 200
        except Exception:
            pass

        # Try to start ZAP from configured path
        zap_path = settings.ZAP_PATH or os.environ.get("ZAP_PATH", "/usr/bin/zap.sh")
        if not os.path.exists(zap_path):
            logger.warning(f"ZAP not found at {zap_path}. Install ZAP or start it manually.")
            return False

        logger.info(f"Starting ZAP daemon from {zap_path}...")
        proc = await asyncio.create_subprocess_exec(
            zap_path, "-daemon", "-port", "8080",
            "-config", f"api.key={self.ZAP_API_KEY}",
            "-config", "api.disablekey=false",
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL,
        )
        # Wait for ZAP to start
        for _ in range(30):
            await asyncio.sleep(2)
            try:
                async with httpx.AsyncClient(timeout=3) as client:
                    r = await client.get(
                        f"{self.ZAP_HOST}/JSON/core/view/version/",
                        params={"apikey": self.ZAP_API_KEY},
                    )
                    if r.status_code == 200:
                        logger.info("ZAP daemon started successfully")
                        return True
            except Exception:
                continue
        logger.error("ZAP daemon failed to start")
        return False

    async def scan(self, target: str, **kwargs) -> ScanResult:
        result = ScanResult(plugin_name=self.name, target=target)
        result.started_at = __import__("datetime").datetime.now()

        running = await self._ensure_zap_running()
        if not running:
            result.status = "failed"
            result.error_message = "ZAP daemon is not available. Install OWASP ZAP or start it manually."
            return result

        try:
            findings = await self._run_scan(target)
            result.findings = findings
            result.risk_score = self.calculate_risk_score(findings)
            result.status = "completed"
        except Exception as e:
            result.status = "failed"
            result.error_message = str(e)
            logger.exception(f"ZAP scan failed for {target}")

        result.completed_at = __import__("datetime").datetime.now()
        return result

    async def _run_scan(self, target: str) -> list[FindingResult]:
        findings = []

        try:
            # 1. Spider the target
            logger.info(f"ZAP spidering {target}")
            spider_resp = await self._zap_api("spider/action/scan", {"url": target})
            scan_id = spider_resp.get("scan", "")

            if scan_id:
                # Wait for spider to complete
                for _ in range(60):
                    await asyncio.sleep(5)
                    status = await self._zap_api("spider/view/status", {"scanId": scan_id})
                    if status.get("status") == "100":
                        break

            # 2. Passive scan (always runs, just wait)
            logger.info("Waiting for passive scan...")
            await asyncio.sleep(10)

            # 3. Active scan
            logger.info(f"ZAP active scanning {target}")
            ascam_resp = await self._zap_api("ascanner/action/scan", {"url": target})
            ascam_id = ascam_resp.get("scan", "")

            if ascam_id:
                for _ in range(120):
                    await asyncio.sleep(5)
                    progress = await self._zap_api("ascanner/view/status", {"scanId": ascam_id})
                    if progress.get("status") == "100":
                        break

            # 4. Get alerts
            alerts = await self._zap_api("core/view/alerts", {"baseurl": target})
            alert_list = alerts.get("alerts", [])

            # Convert to FindingResults
            for alert in alert_list:
                risk = alert.get("risk", "").lower()
                severity_map = {
                    "high": "critical",
                    "medium": "high",
                    "low": "medium",
                    "information": "info",
                    "false positive": "info",
                }
                severity = severity_map.get(risk, "info")

                finding = FindingResult(
                    title=alert.get("name", "ZAP Alert"),
                    description=alert.get("description", ""),
                    severity=severity,
                    category="zap",
                    endpoint=alert.get("url", ""),
                    evidence={
                        "url": alert.get("url"),
                        "param": alert.get("param"),
                        "attack": alert.get("attack"),
                        "evidence": alert.get("evidence"),
                        "cweid": alert.get("cweid"),
                        "wascid": alert.get("wascid"),
                        "reference": alert.get("reference"),
                        "solution": alert.get("solution"),
                    },
                    remediation=alert.get("solution", ""),
                    cwe_id=alert.get("cweid"),
                )

                # Map to OWASP API Top 10 categories
                cwe = alert.get("cweid", 0)
                if cwe in (287, 303, 304, 307, 522, 521):
                    finding.category = "authentication"
                    finding.owasp_category = "API2:2023 - Broken Authentication"
                elif cwe in (285, 639, 862, 863):
                    finding.category = "authorization"
                    finding.owasp_category = "API1:2023 - Broken Object Level Authorization"
                elif cwe in (79, 89, 90, 91, 94, 95, 96, 97, 98):
                    finding.category = "injection"
                    finding.owasp_category = "API8:2023 - Injection"
                elif cwe in (200, 201, 202, 203, 204, 205, 206, 207, 208, 209, 210, 212):
                    finding.category = "information_disclosure"
                    finding.owasp_category = "API3:2023 - Broken Object Property Level Authorization"
                elif cwe in (16, 22, 23, 24, 26, 36, 73, 99, 641):
                    finding.category = "security_misconfiguration"
                    finding.owasp_category = "API8:2023 - Security Misconfiguration"

                findings.append(finding)

            if not alert_list:
                findings.append(
                    FindingResult(
                        title="ZAP Scan Completed",
                        description=f"ZAP spider and active scan completed for {target}. No alerts were raised. "
                                    "Review the full ZAP report for detailed results.",
                        severity="info",
                        category="zap",
                    )
                )

        except Exception as e:
            logger.exception(f"ZAP scan error: {e}")
            findings.append(
                FindingResult(
                    title="ZAP Scan Error",
                    description=f"An error occurred during ZAP scanning: {str(e)}",
                    severity="info",
                    category="zap_error",
                )
            )

        return findings
