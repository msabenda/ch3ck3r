"""AI-powered analysis and enrichment for scanner findings.

Provides intelligent severity re-evaluation, smart remediation suggestions,
OWASP API Top 10 mapping, CWE/CVE enrichment, and risk scoring.
"""
from typing import Optional


class AIAnalyzer:
    """Analyzes scan findings with AI-driven intelligence."""

    # Severity reclassification rules (ML-like heuristic engine)
    SEVERITY_RULES = [
        # Authentication bypass patterns
        {"pattern": ["auth", "bypass", "token", "jwt", "oauth", "session"],
         "boost": "critical",
         "keywords": ["no auth", "missing auth", "token", "bypass", "jwt"]},
        # Data exposure
        {"pattern": ["data", "exposure", "pii", "sensitive", "password", "secret", "key"],
         "boost": "critical",
         "keywords": ["api key", "password", "secret", "token", "credential"]},
        # Injection patterns
        {"pattern": ["injection", "sql", "nosql", "xss", "command"],
         "boost": "critical",
         "keywords": ["injection", "xss", "sql", "nosql", "command"]},
        # IDOR patterns
        {"pattern": ["idor", "object", "authorization", "access control"],
         "boost": "high",
         "keywords": ["id", "user_id", "object", "access"]},
        # SSRF
        {"pattern": ["ssrf", "server", "request", "forgery", "url"],
         "boost": "critical",
         "keywords": ["ssrf", "server-side", "url", "forgery"]},
        # Rate limiting
        {"pattern": ["rate", "limit", "throttle", "dos"],
         "boost": "medium",
         "keywords": ["rate limit", "throttle", "dos"]},
    ]

    REMEDIATION_TEMPLATES = {
        "authentication": (
            "Implement proper authentication using OAuth 2.0 or JWT with short-lived tokens. "
            "Ensure all API endpoints validate tokens and reject unauthenticated requests. "
            "Use refresh token rotation and token revocation. Apply rate limiting on auth endpoints."
        ),
        "authorization": (
            "Apply strict access control checks at every endpoint. "
            "Use role-based access control (RBAC) or attribute-based access control (ABAC). "
            "Verify the authenticated user has permission to access the requested resource. "
            "Test for IDOR vulnerabilities with parameter tampering."
        ),
        "injection": (
            "Use parameterized queries or prepared statements for all database operations. "
            "Apply input validation and sanitization. Use an ORM with proper escaping. "
            "Never concatenate user input directly into queries. Implement a Web Application Firewall."
        ),
        "sensitive_data": (
            "Encrypt sensitive data at rest and in transit using TLS 1.3. "
            "Never log sensitive information. Use environment variables for secrets. "
            "Implement proper key management with rotation policies. Mask PII in responses."
        ),
        "misconfiguration": (
            "Review and harden server configuration. Disable unnecessary HTTP methods. "
            "Set proper CORS headers. Enable security headers (HSTS, CSP, X-Frame-Options). "
            "Remove debug endpoints in production. Use automated configuration scanning."
        ),
        "rate_limiting": (
            "Implement rate limiting per user/IP to prevent abuse. "
            "Use token bucket or sliding window algorithms. "
            "Return proper 429 Too Many Requests responses with Retry-After headers. "
            "Apply different limits for authenticated vs unauthenticated users."
        ),
        "default": (
            "Review the affected endpoint and apply security best practices. "
            "Test with multiple payloads and edge cases. "
            "Implement proper error handling without leaking information. "
            "Consult OWASP documentation for specific remediation guidance."
        ),
    }

    OWASP_MAPPING = {
        "authentication": "API2: Broken Authentication",
        "authorization": "API1: Broken Object Level Authorization",
        "injection": "API8: Injection",
        "sensitive_data": "API3: Broken Object Property Level Authorization",
        "misconfiguration": "API8: Security Misconfiguration",
        "rate_limiting": "API4: Unrestricted Resource Consumption",
        "cors": "API8: Security Misconfiguration",
        "deprecated": "API9: Improper Inventory Management",
    }

    CWE_MAPPING = {
        "authentication": 287,
        "authorization": 862,
        "injection": 94,
        "sensitive_data": 312,
        "misconfiguration": 16,
        "rate_limiting": 770,
        "cors": 942,
        "improper_assets": 1059,
    }

    @classmethod
    def analyze_finding(cls, finding: dict) -> dict:
        """Analyze a finding and return AI-enriched metadata."""
        title = (finding.get("title") or "").lower()
        desc = (finding.get("description") or "").lower()
        category = (finding.get("category") or "").lower()
        combined = f"{title} {desc}"

        # AI severity re-evaluation
        boosted = False
        new_severity = finding.get("severity", "info")
        severity_score = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
        for rule in cls.SEVERITY_RULES:
            if any(kw in combined for kw in rule["keywords"]):
                current = severity_score.get(new_severity, 0)
                boost = severity_score.get(rule["boost"], 0)
                if boost > current:
                    new_severity = rule["boost"]
                    boosted = True

        # Smart remediation
        remediation = finding.get("remediation")
        if not remediation:
            remediation = cls.REMEDIATION_TEMPLATES.get(
                category, cls.REMEDIATION_TEMPLATES["default"]
            )

        # CWE enrichment
        cwe_id = finding.get("cwe_id")
        if not cwe_id:
            cwe_id = cls.CWE_MAPPING.get(category)

        # OWASP mapping
        owasp = finding.get("owasp_category")
        if not owasp:
            owasp = cls.OWASP_MAPPING.get(category, "OWASP API Security Top 10")

        # Risk score contribution
        risk_weights = {
            "critical": 10, "high": 7, "medium": 5, "low": 2, "info": 0.5
        }
        risk_contribution = risk_weights.get(new_severity, 1)

        return {
            "ai_severity": new_severity,
            "ai_boosted": boosted,
            "ai_remediation": remediation,
            "ai_recommended_cwe": cwe_id,
            "ai_owasp_category": owasp,
            "ai_risk_contribution": risk_contribution,
            "ai_confidence": 0.85 if boosted else 0.70,
            "ai_analysis": (
                f"AI analysis: {new_severity.upper()} severity "
                f"with {risk_contribution}/10 risk contribution."
                if boosted else
                f"AI analysis: standard severity at {new_severity}."
            ),
        }

    @classmethod
    def generate_summary(cls, findings: list, risk_score: float) -> dict:
        """Generate an AI executive summary from all findings."""
        enhanced = [cls.analyze_finding(f) for f in findings]
        top_risks = sorted(
            enhanced, key=lambda x: x.get("ai_risk_contribution", 0), reverse=True
        )[:3]

        recommendations = []
        categories = {}
        for f, e in zip(findings, enhanced):
            cat = f.get("category", "unknown")
            if cat not in categories:
                categories[cat] = {"count": 0, "critical": 0, "high": 0, "medium": 0}
            categories[cat]["count"] += 1
            sev = e.get("ai_severity", "info")
            if sev in categories[cat]:
                categories[cat][sev] += 1

        for i, (f, e) in enumerate(zip(findings, enhanced)):
            if i < 5:
                recommendations.append({
                    "priority": i + 1,
                    "title": f"Address {f.get('title', 'finding')}",
                    "description": e.get("ai_remediation", ""),
                    "severity": e.get("ai_severity", "medium"),
                    "ai_boosted": e.get("ai_boosted", False),
                })

        return {
            "ai_summary": (
                f"AI analyzed {len(findings)} findings. "
                f"Risk score: {risk_score}/10."
            ),
            "ai_top_risks": top_risks,
            "ai_recommendations": recommendations,
            "ai_category_breakdown": categories,
            "ai_overall_confidence": (
                "high" if risk_score >= 7
                else "medium" if risk_score >= 3
                else "low"
            ),
        }


class AIRecommendationEngine:
    """Generates intelligent security recommendations based on findings."""

    @staticmethod
    def generate_scan_recommendations(
        findings: list, scan_context: dict = None
    ) -> list:
        """Generate prioritized, actionable recommendations."""
        recs = []
        sev_order = {
            "critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4
        }

        by_cat = {}
        for f in findings:
            c = f.get("category", "unknown")
            if c not in by_cat:
                by_cat[c] = {"count": 0, "severities": {}}
            by_cat[c]["count"] += 1
            sev = f.get("severity", "info")
            by_cat[c]["severities"][sev] = by_cat[c]["severities"].get(sev, 0) + 1

        for i, (cat, info) in enumerate(
            sorted(
                by_cat.items(),
                key=lambda x: max(
                    [sev_order.get(s, 99) for s in x[1]["severities"]]
                ),
            )
        ):
            recs.append({
                "priority": i + 1,
                "category": cat,
                "title": f"Improve {cat.replace('_', ' ').title()} Security",
                "description": (
                    f"Found {info['count']} issues in {cat.replace('_', ' ')} "
                    f"category. Review and apply security controls."
                ),
                "affected_count": info["count"],
            })

        return recs
