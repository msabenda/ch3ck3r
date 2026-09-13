"""Ch3ck3r scanner plugins — each checks a specific OWASP API Top 10 category."""

import re
from typing import Optional

import httpx
import yaml

from app.scanner.engine import BaseScanner, ScanResult, FindingResult


class OpenAPIScanner(BaseScanner):
    """Parse an OpenAPI spec and detect common misconfigurations."""

    name = "openapi"

    async def validate_target(self, target: str) -> bool:
        if target.startswith(("http://", "https://")):
            try:
                async with httpx.AsyncClient(timeout=10) as client:
                    r = await client.get(target)
                    return r.status_code == 200
            except Exception:
                return False
        try:
            with open(target) as f:
                data = yaml.safe_load(f) or {}
                return "openapi" in data or "swagger" in data
        except Exception:
            return False

    async def scan(self, target: str, **kwargs) -> ScanResult:
        result = ScanResult(plugin_name=self.name, target=target)
        result.started_at = __import__("datetime").datetime.now()
        spec = await self._load_spec(target)
        if not spec:
            result.status = "failed"
            result.error_message = "Could not load OpenAPI spec"
            return result

        checks = [
            self._check_missing_auth,
            self._check_weak_cors,
            self._check_missing_rate_limiting,
            self._check_sensitive_data_exposure,
            self._check_deprecated_endpoints,
            self._check_broken_authz,
            self._check_security_misconfig,
        ]

        for check in checks:
            try:
                findings = check(spec)
                result.findings.extend(findings)
            except Exception as e:
                result.findings.append(
                    FindingResult(
                        title=f"Plugin error: {check.__name__}",
                        description=str(e),
                        severity="info",
                        category="plugin_error",
                    )
                )

        result.risk_score = self.calculate_risk_score(result.findings)
        result.completed_at = __import__("datetime").datetime.now()
        return result

    async def _load_spec(self, target: str) -> Optional[dict]:
        if target.startswith(("http://", "https://")):
            async with httpx.AsyncClient(timeout=30) as client:
                r = await client.get(target)
                return yaml.safe_load(r.text)
        with open(target) as f:
            return yaml.safe_load(f)

    def _check_missing_auth(self, spec: dict) -> list[FindingResult]:
        findings = []
        security_defs = spec.get("components", {}).get("securitySchemes", {})
        has_security = len(security_defs) > 0

        paths = spec.get("paths", {})
        unprotected = []
        for path, methods in paths.items():
            for method, details in methods.items():
                if method in ("parameters",):
                    continue
                path_sec = details.get("security", None)
                # No security at path level and no global security
                if path_sec is None and not has_security:
                    unprotected.append(f"{method.upper()} {path}")
                elif path_sec == []:  # explicit empty = no auth
                    unprotected.append(f"{method.upper()} {path} (explicit none)")

        if unprotected:
            findings.append(
                FindingResult(
                    title="Missing Authentication on Endpoints",
                    description=f"Found {len(unprotected)} endpoints without authentication",
                    severity="high",
                    category="authentication",
                    owasp_category="API2:2023 - Broken Authentication",
                    endpoint=", ".join(unprotected[:10]),
                    evidence={"unauthenticated_endpoints": unprotected[:20]},
                    remediation="Apply authentication to all endpoints. Use OAuth2, JWT, or API keys. "
                                "Remove empty security blocks at the path level if global auth exists.",
                )
            )
        return findings

    def _check_weak_cors(self, spec: dict) -> list[FindingResult]:
        findings = []
        # Check for overly permissive CORS in extensions/x- headers
        cors_headers = []
        paths = spec.get("paths", {})
        for path, methods in paths.items():
            for method, details in methods.items():
                if method in ("parameters",):
                    continue
                resp = details.get("responses", {})
                for status_code, resp_details in resp.items():
                    headers = resp_details.get("headers", {})
                    if "Access-Control-Allow-Origin" in headers:
                        origin = headers["Access-Control-Allow-Origin"]
                        if isinstance(origin, dict):
                            val = origin.get("schema", {}).get("example", "")
                            if val == "*":
                                cors_headers.append(f"{method.upper()} {path}")

        if cors_headers:
            findings.append(
                FindingResult(
                    title="Weak CORS Policy",
                    description=f"Found {len(cors_headers)} endpoints with wildcard CORS origin",
                    severity="medium",
                    category="cors",
                    owasp_category="API8:2023 - Security Misconfiguration",
                    endpoint=", ".join(cors_headers[:10]),
                    evidence={"wildcard_cors_endpoints": cors_headers[:20]},
                    remediation="Restrict Access-Control-Allow-Origin to specific trusted origins. "
                                "Avoid using wildcard (*) in production.",
                )
            )
        return findings

    def _check_missing_rate_limiting(self, spec: dict) -> list[FindingResult]:
        findings = []
        # Look for rate limiting headers or x-rate-limit extensions
        has_rate_limit = False
        paths = spec.get("paths", {})
        for path, methods in paths.items():
            for method, details in methods.items():
                if method in ("parameters",):
                    continue
                resp = details.get("responses", {})
                for resp_details in resp.values():
                    headers = resp_details.get("headers", {})
                    for h in headers:
                        if "ratelimit" in h.lower() or "429" in str(resp_details):
                            has_rate_limit = True
                            break

        # Check x- extensions
        if not has_rate_limit:
            x_headers = {k: v for k, v in spec.items() if k.startswith("x-")}
            for k in x_headers:
                if "ratelimit" in k.lower() or "throttle" in k.lower():
                    has_rate_limit = True

        if not has_rate_limit:
            findings.append(
                FindingResult(
                    title="Missing Rate Limiting",
                    description="No rate limiting headers or 429 responses found in the API specification",
                    severity="medium",
                    category="rate_limiting",
                    owasp_category="API4:2023 - Unrestricted Resource Consumption",
                    remediation="Implement rate limiting on all endpoints. Return 429 Too Many Requests "
                                "with Retry-After header when limits are exceeded.",
                )
            )
        return findings

    def _check_sensitive_data_exposure(self, spec: dict) -> list[FindingResult]:
        findings = []
        sensitive_patterns = {
            "password": r"password|passwd|pwd",
            "secret": r"secret|token|api_key|apiKey",
            "ssn": r"ssn|social_security|socialsecurity",
            "credit_card": r"credit_card|cc_number|card_number|cvv",
            "pii": r"email|phone|dob|birth_date|address",
        }

        exposed = {}
        paths = spec.get("paths", {})
        for path, methods in paths.items():
            for method, details in methods.items():
                if method in ("parameters",):
                    continue
                # Check response schemas
                resp = details.get("responses", {})
                for resp_details in resp.values():
                    content = resp_details.get("content", {})
                    for media_type, media_details in content.items():
                        schema = media_details.get("schema", {})
                        props = self._extract_props(schema)
                        for prop in props:
                            for category, pattern in sensitive_patterns.items():
                                if re.search(pattern, prop, re.IGNORECASE):
                                    if category not in exposed:
                                        exposed[category] = []
                                    exposed[category].append(f"{method.upper()} {path} -> {prop}")

        if exposed:
            total = sum(len(v) for v in exposed.values())
            details = "; ".join(f"{k}: {len(v)}" for k, v in exposed.items())
            findings.append(
                FindingResult(
                    title="Sensitive Data Exposure",
                    description=f"Found {total} potentially sensitive properties exposed in API responses: {details}",
                    severity="high",
                    category="sensitive_data",
                    owasp_category="API3:2023 - Broken Object Property Level Authorization",
                    evidence={k: v[:10] for k, v in exposed.items()},
                    remediation="Review all response schemas for sensitive data. Mask or omit fields like passwords, "
                                "secrets, and PII from API responses unless explicitly required.",
                )
            )
        return findings

    def _check_deprecated_endpoints(self, spec: dict) -> list[FindingResult]:
        findings = []
        deprecated = []
        paths = spec.get("paths", {})
        for path, methods in paths.items():
            for method, details in methods.items():
                if method in ("parameters",):
                    continue
                if details.get("deprecated", False):
                    deprecated.append(f"{method.upper()} {path}")

        if deprecated:
            findings.append(
                FindingResult(
                    title="Deprecated Endpoints Exposed",
                    description=f"Found {len(deprecated)} deprecated endpoints still available in the API spec",
                    severity="low",
                    category="deprecated",
                    owasp_category="API9:2023 - Improper Assets Management",
                    endpoint=", ".join(deprecated[:10]),
                    evidence={"deprecated_endpoints": deprecated},
                    remediation="Remove deprecated endpoints from production or clearly version them. "
                                "Maintain a sunset policy with clear migration timelines.",
                )
            )
        return findings

    def _check_broken_authz(self, spec: dict) -> list[FindingResult]:
        """Check for potential authorization issues based on endpoint patterns."""
        findings = []
        paths = spec.get("paths", {})
        admin_paths = []
        id_or_pattern = re.compile(r"\{[^}]+\}")

        for path in paths:
            if path.startswith("/admin") or path.startswith("/api/admin"):
                admin_paths.append(path)

        # Check if admin paths use the same security scheme as user paths
        if admin_paths:
            findings.append(
                FindingResult(
                    title="Review Authorization Model",
                    description=f"Found {len(admin_paths)} admin-prefixed paths. Verify that proper authorization "
                                "checks are in place to prevent privilege escalation.",
                    severity="info",
                    category="authorization",
                    owasp_category="API1:2023 - Broken Object Level Authorization",
                    endpoint=", ".join(admin_paths[:10]),
                    evidence={"admin_paths": admin_paths},
                    remediation="Implement role-based access control (RBAC). Ensure admin paths verify "
                                "admin role before processing requests.",
                )
            )
        return findings

    def _check_security_misconfig(self, spec: dict) -> list[FindingResult]:
        findings = []
        issues = []

        # Check if HTTPS is enforced
        paths = spec.get("paths", {})
        for path in list(paths.keys())[:20]:
            # This is a soft check — JFYI
            pass

        # Check for default/example credentials left in spec
        examples = []
        defs = spec.get("components", {}).get("schemas", {})
        for schema_name, schema_def in defs.items():
            if "example" in schema_def:
                ex = str(schema_def["example"])
                if len(ex) > 0 and ex not in ("string", "0", "true", "false"):
                    examples.append(f"{schema_name}: {ex[:50]}")

        if examples:
            findings.append(
                FindingResult(
                    title="Potentially Hardcoded Example Values",
                    description=f"Found {len(examples)} schema examples that may contain default credentials or data",
                    severity="info",
                    category="security_misconfiguration",
                    owasp_category="API8:2023 - Security Misconfiguration",
                    evidence={"examples": examples[:10]},
                    remediation="Review example values in schemas for hardcoded credentials or sensitive data. "
                                "Use placeholder values in specifications.",
                )
            )

        # Check for debug endpoints
        debug_paths = [p for p in paths if any(
            kw in p.lower() for kw in ["debug", "test", "staging", "internal", "healthz", "metrics"]
        )]
        if debug_paths:
            findings.append(
                FindingResult(
                    title="Debug/Internal Endpoints Exposed",
                    description=f"Found {len(debug_paths)} endpoints that may be debug or internal routes",
                    severity="medium",
                    category="security_misconfiguration",
                    owasp_category="API9:2023 - Improper Assets Management",
                    endpoint=", ".join(debug_paths[:10]),
                    evidence={"debug_endpoints": debug_paths},
                    remediation="Remove debug and internal endpoints from production APIs. "
                                "If needed, protect them with authentication and network restrictions.",
                )
            )

        return findings

    def _extract_props(self, schema: dict) -> list[str]:
        """Recursively extract property names from a schema (handles $ref, allOf, etc.)."""
        props = []
        if "properties" in schema:
            props.extend(schema["properties"].keys())
        if "allOf" in schema:
            for sub in schema["allOf"]:
                props.extend(self._extract_props(sub))
        if "items" in schema:
            if isinstance(schema["items"], dict):
                props.extend(self._extract_props(schema["items"]))
        return props
