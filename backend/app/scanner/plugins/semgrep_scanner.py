"""Semgrep scanner plugin — runs Semgrep SAST rules for API security."""

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


class SemgrepScanner(BaseScanner):
    """Wrapper for Semgrep SAST scanner.

    Analyzes source code for security vulnerabilities with API-focused rules.
    Can scan local files or clone repos.
    """

    name = "semgrep"

    # Custom API security rules (embedded as YAML)
    API_SECURITY_RULES = """
rules:
  - id: hardcoded-api-key
    pattern-either:
      - pattern: 'api_key = "$KEY"'
      - pattern: 'apikey = "$KEY"'
      - pattern: 'API_KEY = "$KEY"'
      - pattern: 'apiKey: "$KEY"'
    message: "Hardcoded API key detected"
    severity: ERROR
    languages: [python, javascript, typescript, go, java, ruby, rust]
    metadata:
      category: security
      owasp: "API2:2023 - Broken Authentication"

  - id: weak-jwt-secret
    patterns:
      - pattern-either:
          - pattern: 'jwt.encode(..., "secret", ...)'
          - pattern: 'JWT.encode(..., "secret", ...)'
          - pattern: 'jwt.sign(..., "secret", ...)'
          - pattern: "JWT_SECRET = '...'"
      - pattern-not: 'JWT_SECRET = "${{ SECRET }}"'
      - pattern-not: 'jwt.encode(..., os.environ["..."], ...)'
    message: "Potentially weak JWT secret - use strong random secrets from environment"
    severity: WARNING
    languages: [python, javascript, typescript, go, java, ruby]
    metadata:
      category: security
      owasp: "API2:2023 - Broken Authentication"

  - id: disabled-auth-decorator
    patterns:
      - pattern-either:
          - pattern: '@login_required'
          - pattern: '@jwt_required()'
          - pattern: 'authenticate_request'
      - pattern-inside: |
          def test_...():
            ...
      - pattern-not-inside: |
          def ...():
            ...
      - metavariable-pattern:
          metavariable: $FUNC
          pattern: '(..._test_...)'
    message: "Authentication bypass in test code"
    severity: WARNING
    languages: [python, javascript, typescript]
    metadata:
      category: security
      owasp: "API1:2023 - Broken Object Level Authorization"

  - id: debug-endpoint
    pattern-either:
      - pattern: '@app.route("/debug", ...)'
      - pattern: '@app.route("/dev", ...)'
      - pattern: 'router.add_route("/debug", ...)'
      - pattern: 'server.route("/internal", ...)'
    message: "Debug or internal endpoint exposed - remove in production"
    severity: WARNING
    languages: [python, javascript, typescript, go, java, ruby]
    metadata:
      category: security
      owasp: "API9:2023 - Improper Assets Management"

  - id: cors-wildcard
    pattern-either:
      - pattern: 'Access-Control-Allow-Origin: "*"'
      - pattern: 'allow_origins=["*"]'
      - pattern: 'origins: "*"'
      - pattern: 'Access-Control-Allow-Origin: *'
    message: "Wildcard CORS policy detected - specify allowed origins"
    severity: WARNING
    languages: [generic]
    metadata:
      category: security
      owasp: "API8:2023 - Security Misconfiguration"

  - id: disable-ssl-verification
    pattern-either:
      - pattern: 'verify=False'
      - pattern: 'verify: false'
      - pattern: 'ssl_verify=False'
      - pattern: 'insecure_skip_verify=True'
    message: "SSL/TLS verification disabled - security risk"
    severity: ERROR
    languages: [python, javascript, typescript, go, java, ruby, rust]
    metadata:
      category: security
      owasp: "API8:2023 - Security Misconfiguration"

  - id: sql-injection-risk
    patterns:
      - pattern-either:
          - pattern: 'execute(f"...{...}...")'
          - pattern: "execute('...' + ... + '...')"
          - pattern: 'query(f"...{...}...")'
      - pattern-not: 'execute(..., ..., ...)'
    message: "Potential SQL injection - use parameterized queries"
    severity: ERROR
    languages: [python, javascript, typescript, go, java, ruby, rust]
    metadata:
      category: security
      owasp: "API8:2023 - Injection"

  - id: mass-assignment
    pattern-either:
      - pattern: |
          $MODEL.objects.update_or_create(...$REQ.data...)
      - pattern: |
          $MODEL.update(...$REQ.json...)
      - pattern: |
          db.save(...$BODY...)
    message: "Potential mass assignment vulnerability - validate user input"
    severity: WARNING
    languages: [python, javascript, typescript, go, java, ruby]
    metadata:
      category: security
      owasp: "API1:2023 - Broken Object Level Authorization"

  - id: missing-rate-limit
    pattern-either:
      - pattern: |
          @app.route(...)
          def ...():
            ...
      - pattern: |
          router.get(...)
      - pattern: |
          async def get(...):
            ...
    patterns:
      - pattern-not: '@limit(...)'
      - pattern-not: '@rate_limit(...)'
      - pattern-not: 'limiter.limit(...)'
      - pattern-not: 'rate_limit(...)'
    message: "Endpoint appears to be missing rate limiting"
    severity: WARNING
    languages: [python, javascript, typescript]
    metadata:
      category: security
      owasp: "API4:2023 - Unrestricted Resource Consumption"

  - id: stacktrace-exposure
    pattern-either:
      - pattern: 'traceback.print_exc()'
      - pattern: 'print(e.with_traceback(...))'
      - pattern: 'console.error(err.stack)'
      - pattern: 'logger.exception(err)'
    message: "Stack traces may expose internal implementation details"
    severity: WARNING
    languages: [python, javascript, typescript, go, java, ruby, rust]
    metadata:
      category: security
      owasp: "API3:2023 - Broken Object Property Level Authorization"
"""

    async def validate_target(self, target: str) -> bool:
        # Accept file paths, git repos, and URLs
        if target.startswith(("http://", "https://", "git@")):
            return True
        return os.path.exists(target)

    def _get_semgrep_path(self) -> str:
        return settings.SEMGREP_PATH or os.environ.get("SEMGREP_PATH", "semgrep")

    async def scan(self, target: str, **kwargs) -> ScanResult:
        result = ScanResult(plugin_name=self.name, target=target)
        result.started_at = __import__("datetime").datetime.now()

        semgrep_path = self._get_semgrep_path()

        # Check if semgrep is available
        try:
            proc = await asyncio.create_subprocess_exec(
                semgrep_path, "--version",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            await asyncio.wait_for(proc.communicate(), timeout=10)
            if proc.returncode != 0:
                raise FileNotFoundError("semgrep not found")
        except Exception:
            result.status = "failed"
            result.error_message = (
                "Semgrep is not installed. Install with: pip install semgrep"
            )
            return result

        try:
            findings = await self._run_semgrep(target, semgrep_path)
            result.findings = findings
            result.risk_score = self.calculate_risk_score(findings)
            result.status = "completed"
        except Exception as e:
            result.status = "failed"
            result.error_message = str(e)
            logger.exception(f"Semgrep scan failed for {target}")

        result.completed_at = __import__("datetime").datetime.now()
        return result

    async def _run_semgrep(self, target: str, semgrep_path: str) -> list[FindingResult]:
        findings = []

        # Handle git repos
        scan_target = target
        temp_dir = None
        if target.startswith(("http://", "https://", "git@")):
            temp_dir = tempfile.mkdtemp()
            repo_name = target.split("/")[-1].replace(".git", "")
            scan_target = os.path.join(temp_dir, repo_name)
            logger.info(f"Cloning {target} to {scan_target}")
            clone_proc = await asyncio.create_subprocess_exec(
                "git", "clone", "--depth", "1", target, scan_target,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            await asyncio.wait_for(clone_proc.communicate(), timeout=120)
            if clone_proc.returncode != 0:
                findings.append(
                    FindingResult(
                        title="Repository Clone Failed",
                        description=f"Failed to clone repository: {target}",
                        severity="info",
                        category="semgrep_error",
                    )
                )
                return findings

        # Create rules file
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            f.write(self.API_SECURITY_RULES)
            rules_path = f.name

        # Create output file
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            output_path = f.name

        try:
            # Run semgrep with custom + standard rules
            cmd = [
                semgrep_path,
                "--config", rules_path,
                "--config", "p/owasp-top-ten",
                "--config", "p/security-audit",
                "--json",
                "--json-output", output_path,
                "--metrics", "off",
                "--no-error",
                scan_target,
            ]

            logger.info(f"Running semgrep on {scan_target}")

            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )

            try:
                await asyncio.wait_for(proc.communicate(), timeout=settings.SCAN_TIMEOUT_SECONDS)
            except asyncio.TimeoutError:
                proc.kill()
                findings.append(
                    FindingResult(
                        title="Semgrep Scan Timed Out",
                        description=f"Semgrep exceeded {settings.SCAN_TIMEOUT_SECONDS}s timeout",
                        severity="info",
                        category="semgrep_error",
                    )
                )
                return findings

            # Parse results
            if os.path.exists(output_path):
                with open(output_path) as f:
                    data = json.load(f)
                    results = data.get("results", [])
                    for r in results:
                        finding = self._parse_semgrep_result(r)
                        if finding:
                            findings.append(finding)

            if not findings:
                findings.append(
                    FindingResult(
                        title="Semgrep Scan Completed",
                        description=f"Semgrep scan completed for {target}. No API security issues detected.",
                        severity="info",
                        category="semgrep",
                    )
                )

        finally:
            # Cleanup
            try:
                os.unlink(rules_path)
                os.unlink(output_path)
            except Exception:
                pass
            if temp_dir:
                import shutil
                shutil.rmtree(temp_dir, ignore_errors=True)

        return findings

    def _parse_semgrep_result(self, result: dict) -> Optional[FindingResult]:
        """Convert a Semgrep result to FindingResult."""
        check_id = result.get("check_id", "")
        path = result.get("path", "")
        start_line = result.get("start", {}).get("line", 0)
        end_line = result.get("end", {}).get("line", 0)
        extra = result.get("extra", {})

        severity_raw = extra.get("severity", "INFO").lower()
        severity_map = {
            "error": "critical",
            "warning": "high",
            "info": "medium",
            "none": "info",
        }
        severity = severity_map.get(severity_raw, "info")

        message = extra.get("message", "Semgrep finding")
        lines = extra.get("lines", "")
        metadata = extra.get("metadata", {})

        # Extract code snippet
        code_snippet = lines.strip() if lines else ""

        # Determine category from rule metadata
        category = "semgrep"
        owasp_category = None

        rule_owasp = metadata.get("owasp", "")
        if rule_owasp:
            owasp_category = rule_owasp
            if "Authentication" in rule_owasp:
                category = "authentication"
            elif "Authorization" in rule_owasp:
                category = "authorization"
            elif "Misconfiguration" in rule_owasp:
                category = "security_misconfiguration"
            elif "Injection" in rule_owasp:
                category = "injection"
            elif "Asset" in rule_owasp:
                category = "deprecated"
            elif "Resource" in rule_owasp:
                category = "rate_limiting"
            elif "Property" in rule_owasp:
                category = "sensitive_data"
        else:
            # Infer from check_id
            if "auth" in check_id.lower():
                category = "authentication"
                owasp_category = "API2:2023 - Broken Authentication"
            elif "jwt" in check_id.lower():
                category = "authentication"
                owasp_category = "API2:2023 - Broken Authentication"
            elif "sql" in check_id.lower() or "injection" in check_id.lower():
                category = "injection"
                owasp_category = "API8:2023 - Injection"
            elif "cors" in check_id.lower():
                category = "cors"
                owasp_category = "API8:2023 - Security Misconfiguration"
            elif "debug" in check_id.lower() or "exposed" in check_id.lower():
                category = "security_misconfiguration"
                owasp_category = "API9:2023 - Improper Assets Management"
            elif "secret" in check_id.lower() or "hardcoded" in check_id.lower():
                category = "sensitive_data"
                owasp_category = "API3:2023 - Broken Object Property Level Authorization"

        endpoint = f"{path}:{start_line}-{end_line}"

        evidence = {
            "check_id": check_id,
            "file": path,
            "lines": f"{start_line}-{end_line}",
            "code_snippet": code_snippet,
            "metadata": {
                k: v for k, v in metadata.items()
                if k in ("category", "technology", "confidence", "references")
            },
        }

        # Build remediation from semgrep fix if available
        remediation = extra.get("fix", "")
        if not remediation:
            remediation = (
                f"Review the code at {path}:{start_line}. "
                "Apply security best practices for the detected issue."
            )

        return FindingResult(
            title=check_id.split(".")[-1].replace("-", " ").title(),
            description=message,
            severity=severity,
            category=category,
            owasp_category=owasp_category,
            endpoint=endpoint,
            evidence=evidence,
            remediation=remediation,
        )
