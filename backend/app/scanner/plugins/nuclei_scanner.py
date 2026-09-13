"""Nuclei scanner plugin — runs Nuclei templates for API security scanning."""

import asyncio
import json
import logging
import os
import tempfile
from typing import Optional

from app.scanner.engine import BaseScanner, ScanResult, FindingResult
from app.core.config import get_settings

logger = logging.getLogger(__name__)
settings = get_settings()


class NucleiScanner(BaseScanner):
    """Wrapper for ProjectDiscovery Nuclei.

    Runs nuclei with API-focused templates against targets.
    Requires nuclei binary in PATH or configured via NUCLEI_PATH.
    """

    name = "nuclei"

    async def validate_target(self, target: str) -> bool:
        return target.startswith(("http://", "https://"))

    def _get_nuclei_path(self) -> str:
        path = settings.NUCLEI_PATH or os.environ.get("NUCLEI_PATH", "nuclei")
        return path

    async def scan(self, target: str, **kwargs) -> ScanResult:
        result = ScanResult(plugin_name=self.name, target=target)
        result.started_at = __import__("datetime").datetime.now()

        nuclei_path = self._get_nuclei_path()

        # Check if nuclei is available
        try:
            proc = await asyncio.create_subprocess_exec(
                nuclei_path, "-version",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            await asyncio.wait_for(proc.communicate(), timeout=10)
            if proc.returncode != 0:
                raise FileNotFoundError("nuclei not found")
        except Exception:
            result.status = "failed"
            result.error_message = (
                "Nuclei is not installed or not in PATH. "
                "Install from https://github.com/projectdiscovery/nuclei or set NUCLEI_PATH."
            )
            return result

        try:
            findings = await self._run_nuclei(target, nuclei_path)
            result.findings = findings
            result.risk_score = self.calculate_risk_score(findings)
            result.status = "completed"
        except Exception as e:
            result.status = "failed"
            result.error_message = str(e)
            logger.exception(f"Nuclei scan failed for {target}")

        result.completed_at = __import__("datetime").datetime.now()
        return result

    async def _run_nuclei(self, target: str, nuclei_path: str) -> list[FindingResult]:
        findings = []

        # Create temp file for JSON output
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            output_path = f.name

        try:
            # Focus on API-relevant templates
            templates = [
                "exposed-panels",
                "exposed-apis",
                "misconfiguration",
                "cors",
                "takeovers",
                "default-logins",
                "tech-detect",
            ]

            # Run nuclei with multiple template categories
            cmd = [
                nuclei_path,
                "-target", target,
                "-jsonl",
                "-o", output_path,
                "-severity", "critical,high,medium,low",
                "-rate-limit", "150",
                "-concurrency", "50",
                "-timeout", "10",
            ]

            # Add API-specific templates
            for tmpl in templates:
                cmd.extend(["-tags", tmpl])

            logger.info(f"Running nuclei: {' '.join(cmd)}")

            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )

            try:
                await asyncio.wait_for(proc.communicate(), timeout=settings.SCAN_TIMEOUT_SECONDS)
            except asyncio.TimeoutError:
                proc.kill()
                logger.warning(f"Nuclei timed out for {target}")
                findings.append(
                    FindingResult(
                        title="Nuclei Scan Timed Out",
                        description=f"Nuclei scan exceeded {settings.SCAN_TIMEOUT_SECONDS}s timeout. "
                                    "Results may be incomplete.",
                        severity="info",
                        category="nuclei",
                    )
                )
                return findings

            # Parse results
            if os.path.exists(output_path):
                with open(output_path) as f:
                    for line in f:
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            data = json.loads(line)
                            finding = self._parse_nuclei_result(data)
                            if finding:
                                findings.append(finding)
                        except json.JSONDecodeError:
                            continue

            if not findings:
                findings.append(
                    FindingResult(
                        title="Nuclei Scan Completed",
                        description=f"Nuclei scan completed for {target}. No vulnerabilities detected "
                                    "with the selected templates.",
                        severity="info",
                        category="nuclei",
                    )
                )

        finally:
            # Cleanup temp file
            try:
                os.unlink(output_path)
            except Exception:
                pass

        return findings

    def _parse_nuclei_result(self, data: dict) -> Optional[FindingResult]:
        """Convert a Nuclei JSON result to FindingResult."""
        severity_raw = data.get("info", {}).get("severity", "info").lower()
        severity_map = {
            "critical": "critical",
            "high": "high",
            "medium": "medium",
            "low": "low",
            "info": "info",
            "unknown": "info",
        }
        severity = severity_map.get(severity_raw, "info")

        template_id = data.get("template-id", "")
        name = data.get("info", {}).get("name", f"Nuclei: {template_id}")
        description = data.get("info", {}).get("description", "")
        matched = data.get("matched-at", data.get("url", ""))
        extracted = data.get("extracted-results", [])
        curl = data.get("curl-command", "")

        # Map to OWASP categories based on template tags
        tags = data.get("info", {}).get("tags", [])
        owasp_category = None
        category = "nuclei"

        tag_category_map = {
            "auth": ("authentication", "API2:2023 - Broken Authentication"),
            "cors": ("cors", "API8:2023 - Security Misconfiguration"),
            "jwt": ("authentication", "API2:2023 - Broken Authentication"),
            "exposure": ("information_disclosure", "API3:2023 - Broken Object Property Level Authorization"),
            "config": ("security_misconfiguration", "API8:2023 - Security Misconfiguration"),
            "injection": ("injection", "API8:2023 - Injection"),
            "rate-limit": ("rate_limiting", "API4:2023 - Unrestricted Resource Consumption"),
            "deprecated": ("deprecated", "API9:2023 - Improper Assets Management"),
        }

        for tag in tags:
            if tag in tag_category_map:
                category, owasp_category = tag_category_map[tag]
                break

        evidence = {
            "template_id": template_id,
            "matched_at": matched,
            "extracted_results": extracted,
            "curl_command": curl,
            "tags": tags,
            "raw_data": data.get("info", {}),
        }

        # Build remediation from template metadata
        remediation = data.get("info", {}).get("remediation", "")
        if not remediation:
            remediation = (
                f"Review the detected issue at {matched}. "
                "Apply security best practices for the affected component."
            )

        # CVE/CWE mapping
        cve_id = None
        cwe_id = None
        classification = data.get("info", {}).get("classification", {})
        if classification:
            cve_id = classification.get("cve-id", [None])[0] if isinstance(classification.get("cve-id"), list) else None
            cwe_id = classification.get("cwe-id", [None])[0] if isinstance(classification.get("cwe-id"), list) else None

        return FindingResult(
            title=name,
            description=description,
            severity=severity,
            category=category,
            owasp_category=owasp_category,
            endpoint=matched,
            evidence=evidence,
            remediation=remediation,
            cve_id=cve_id,
            cwe_id=cwe_id,
        )
