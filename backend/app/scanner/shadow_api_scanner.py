"""Shadow API scanner — detects undocumented, deprecated, and zombie API endpoints.

Uses common API path patterns, versioning heuristics, and known API fingerprints
to discover shadow/rogue APIs running on a target.
"""
from typing import List, Dict, Optional
import httpx
import asyncio
import re
from urllib.parse import urlparse


class ShadowAPIScanner:
    """Scans for shadow/rogue API endpoints on a target host."""

    # Common undocumented API path patterns to probe
    SHADOW_PATHS = [
        # Admin/debug endpoints
        "/api/admin", "/api/debug", "/api/health", "/api/status",
        "/api/metrics", "/api/info", "/api/docs", "/api/swagger",
        "/api/swagger.json", "/api/swagger.yaml", "/api/openapi.json",
        "/api/graphql", "/api/playground", "/api/console",
        "/api/actuator", "/api/actuator/health", "/api/actuator/info",
        "/admin", "/debug", "/health", "/status", "/info",
        "/metrics", "/docs", "/swagger", "/swagger.json",
        "/openapi.json", "/actuator", "/actuator/health",
        # Common API version variants
        "/api/v2", "/api/v3", "/api/v4", "/api/v5",
        "/v2", "/v3", "/v1.1", "/v2.0",
        # Internal/staging endpoints
        "/api/internal", "/api/staging", "/api/test",
        "/api/qa", "/api/dev", "/api/demo",
        "/internal", "/staging", "/test",
        # Sensitive operations
        "/api/users/admin", "/api/config", "/api/settings",
        "/api/backup", "/api/export", "/api/import",
        "/api/migrate", "/api/reset", "/api/purge",
        "/api/logs", "/api/audit", "/api/audit-logs",
        # Deprecated API patterns (zombie APIs)
        "/api/v0", "/api/v0.1", "/api/v0.9",
        "/api/legacy", "/api/old", "/api/deprecated",
        "/api/v1/deprecated", "/api/v1/legacy",
        # Framework-specific
        "/api/__debug__", "/api/.env", "/api/.git/config",
        "/api/phpinfo.php", "/api/info.php",
        "/__debug__", "/.env", "/.git/config",
        # Common API proxies/gateways
        "/api/proxy", "/api/gateway", "/api/bridge",
        "/proxy", "/gateway",
        # Cloud/third-party integrations
        "/api/webhook", "/api/webhooks", "/api/callback",
        "/api/hook", "/api/notify", "/api/notification",
        "/webhook", "/webhooks",
    ]

    # HTTP method variations to test per path
    METHODS = ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"]

    # API version fingerprints for known frameworks
    FRAMEWORK_FINGERPRINTS = {
        "FastAPI": {"headers": {"server": "uvicorn"}, "paths": ["/docs", "/openapi.json", "/redoc"]},
        "Flask": {"headers": {"server": "Werkzeug"}, "paths": []},
        "Django REST": {"headers": {}, "paths": ["/api-auth/", "/api-token-auth/"]},
        "Express.js": {"headers": {"x-powered-by": "Express"}, "paths": []},
        "Spring Boot": {"headers": {}, "paths": ["/actuator", "/actuator/health"]},
        "ASP.NET Core": {"headers": {"server": "Kestrel"}, "paths": []},
    }

    @staticmethod
    async def probe_endpoint(
        client: httpx.AsyncClient,
        base_url: str,
        path: str,
        method: str = "GET",
    ) -> Optional[Dict]:
        """Probe a single endpoint path with a given HTTP method."""
        url = f"{base_url.rstrip('/')}{path}"
        try:
            resp = await client.request(method, url, timeout=3.0)
            # Any non-404 response suggests the endpoint exists
            if resp.status_code not in (404, 405, 410):
                return {
                    "path": path,
                    "method": method,
                    "status_code": resp.status_code,
                    "status_text": resp.reason_phrase or "",
                    "content_type": resp.headers.get("content-type", ""),
                    "content_length": len(resp.content),
                    "server": resp.headers.get("server", ""),
                    "detected": True,
                }
        except (httpx.TimeoutException, httpx.ConnectError, httpx.RequestError):
            return None
        except Exception:
            return None
        return None

    @staticmethod
    async def scan(
        target_url: str,
        concurrency: int = 40,
        depth: str = "standard",
    ) -> Dict:
        """Run shadow API scan against a target URL."""
        parsed = urlparse(target_url)
        base = f"{parsed.scheme}://{parsed.netloc}"
        results = {
            "target": target_url,
            "base": base,
            "shadow_endpoints": [],
            "frameworks_detected": [],
            "risk_factors": [],
            "shadow_api_risk_score": 0,
        }

        paths = ShadowAPIScanner.SHADOW_PATHS

        # Probe with concurrency
        async with httpx.AsyncClient(
            follow_redirects=True,
            verify=False,
            timeout=5.0,
            headers={
                "User-Agent": "Ch3ck3r-Security-Scanner/2.0",
                "Accept": "*/*",
            },
        ) as client:
            # Probe primary paths (GET)
            sem = asyncio.Semaphore(concurrency)

            async def bounded_probe(path):
                async with sem:
                    return await ShadowAPIScanner.probe_endpoint(client, base, path)

            tasks = [bounded_probe(path) for path in paths]
            probe_results = await asyncio.gather(*tasks, return_exceptions=True)

            for pr in probe_results:
                if isinstance(pr, dict) and pr.get("detected"):
                    results["shadow_endpoints"].append(pr)

            # Probe first few paths with multiple methods (concurrent)
            multi_method_paths = paths[:5]
            mm_tasks = []
            for path in multi_method_paths:
                for method in ["POST", "PUT", "DELETE", "PATCH"]:
                    mm_tasks.append(
                        ShadowAPIScanner.probe_endpoint(client, base, path, method)
                    )
            mm_results = await asyncio.gather(*mm_tasks, return_exceptions=True)
            for result in mm_results:
                if isinstance(result, dict) and result.get("detected"):
                    results["shadow_endpoints"].append(result)

            # Framework detection
            frameworks_paths = ["/openapi.json", "/docs", "/actuator/health", "/health"]
            for fw_path in frameworks_paths:
                try:
                    resp = await client.get(f"{base}{fw_path}", timeout=3.0)
                    if resp.status_code == 200:
                        text = resp.text.lower()
                        if "openapi" in text or "swagger" in text:
                            results["frameworks_detected"].append("OpenAPI Spec Available")
                        if "spring" in text or "actuator" in text:
                            results["frameworks_detected"].append("Spring Boot / Actuator")
                        if "graphql" in text:
                            results["frameworks_detected"].append("GraphQL API")
                except Exception:
                    pass

        # Risk analysis
        shadow_count = len(results["shadow_endpoints"])
        if shadow_count > 0:
            results["risk_factors"].append(
                f"{shadow_count} shadow/undocumented endpoints detected"
            )
            results["shadow_api_risk_score"] = min(shadow_count * 15, 100)

        # Check for critical findings
        admin_endpoints = [
            e for e in results["shadow_endpoints"]
            if any(kw in e["path"].lower() for kw in ["admin", "debug", "config", "backup"])
        ]
        if admin_endpoints:
            results["risk_factors"].append(
                f"{len(admin_endpoints)} admin/debug endpoints exposed"
            )
            results["shadow_api_risk_score"] = min(
                results["shadow_api_risk_score"] + len(admin_endpoints) * 20, 100
            )

        # Check for deprecated API versions
        deprecated = [
            e for e in results["shadow_endpoints"]
            if any(kw in e["path"] for kw in ["v0", "legacy", "old", "deprecated"])
        ]
        if deprecated:
            results["risk_factors"].append(
                f"{len(deprecated)} deprecated (zombie) API endpoints still active"
            )
            results["shadow_api_risk_score"] = min(
                results["shadow_api_risk_score"] + len(deprecated) * 25, 100
            )

        # Check for sensitive data exposure
        sensitive_paths = [
            e for e in results["shadow_endpoints"]
            if any(
                kw in e["path"].lower()
                for kw in [".env", ".git", "phpinfo", "info.php", "config", "backup", "logs", "audit"]
            )
        ]
        if sensitive_paths:
            results["risk_factors"].append(
                f"{len(sensitive_paths)} sensitive data exposure endpoints"
            )

        results["shadow_api_risk_score"] = round(results["shadow_api_risk_score"], 1)

        return results


# ── Public Test APIs for Demo/Validation ──────────────────────────

PUBLIC_TEST_APIS = [
    {
        "name": "REST API",
        "url": "https://jsonplaceholder.typicode.com",
        "description": "Free fake REST API for testing and prototyping (JSONPlaceholder)",
        "category": "REST",
        "docs": "https://jsonplaceholder.typicode.com/guide/",
        "endpoints": 7,
        "auth": "None",
    },
    {
        "name": "Petstore (Swagger)",
        "url": "https://petstore.swagger.io/v2",
        "description": "Swagger Petstore — standard OpenAPI demo with pets, orders, and users",
        "category": "OpenAPI",
        "docs": "https://petstore.swagger.io/",
        "endpoints": 20,
        "auth": "api_key",
    },
    {
        "name": "HTTPBin",
        "url": "https://httpbin.org",
        "description": "HTTP request & response testing service with auth, delay, and status code endpoints",
        "category": "REST",
        "docs": "https://httpbin.org/",
        "endpoints": 50,
        "auth": "None",
    },
    {
        "name": "ReqRes",
        "url": "https://reqres.in/api",
        "description": "Mock REST API for user management with CRUD, pagination, and delayed responses",
        "category": "REST",
        "docs": "https://reqres.in/",
        "endpoints": 12,
        "auth": "None",
    },
    {
        "name": "PokeAPI",
        "url": "https://pokeapi.co/api/v2",
        "description": "Pokémon data API — RESTful with extensive resource tree",
        "category": "REST",
        "docs": "https://pokeapi.co/docs/v2",
        "endpoints": 50,
        "auth": "None",
    },
    {
        "name": "GitHub API",
        "url": "https://api.github.com",
        "description": "GitHub REST API — public repos, users, issues, and rate limit info",
        "category": "REST",
        "docs": "https://docs.github.com/en/rest",
        "endpoints": 100,
        "auth": "Optional (token)",
    },
    {
        "name": "Cat Facts",
        "url": "https://catfact.ninja/fact",
        "description": "Simple REST API returning random cat facts",
        "category": "REST",
        "docs": "https://catfact.ninja/",
        "endpoints": 4,
        "auth": "None",
    },
    {
        "name": "CoinDesk (BTC)",
        "url": "https://api.coindesk.com/v1/bpi/currentprice.json",
        "description": "Bitcoin price index API — real-time BTC price in multiple currencies",
        "category": "REST",
        "docs": "https://www.coindesk.com/coindesk-api",
        "endpoints": 5,
        "auth": "None",
    },
    {
        "name": "Open Brewery DB",
        "url": "https://api.openbrewerydb.org/breweries",
        "description": "Open database of breweries, cideries, and brewpubs — RESTful",
        "category": "REST",
        "docs": "https://www.openbrewerydb.org/documentation",
        "endpoints": 8,
        "auth": "None",
    },
    {
        "name": "SpaceX (unofficial)",
        "url": "https://api.spacexdata.com/v4",
        "description": "Unofficial SpaceX REST API — rockets, launches, capsules, crew",
        "category": "REST",
        "docs": "https://github.com/r-spacex/SpaceX-API",
        "endpoints": 30,
        "auth": "None",
    },
    {
        "name": "Jikan (MyAnimeList)",
        "url": "https://api.jikan.moe/v4",
        "description": "Unofficial MyAnimeList REST API — anime, manga, character data",
        "category": "REST",
        "docs": "https://docs.api.jikan.moe/",
        "endpoints": 40,
        "auth": "None",
    },
    {
        "name": "Open Weather",
        "url": "https://api.openweathermap.org/data/2.5/weather",
        "description": "Current weather data for cities worldwide (requires API key)",
        "category": "REST",
        "docs": "https://openweathermap.org/api",
        "endpoints": 6,
        "auth": "api_key",
    },
]

PUBLIC_TEST_APIS_BY_CATEGORY = {
    "best_all_around": [
        "jsonplaceholder.typicode.com",
        "petstore.swagger.io",
        "httpbin.org",
    ],
    "easy_no_auth": [
        "jsonplaceholder.typicode.com",
        "reqres.in",
        "catfact.ninja",
        "api.openbrewerydb.org",
    ],
    "large_attack_surface": [
        "api.github.com",
        "api.spacexdata.com",
        "api.jikan.moe",
        "pokeapi.co",
    ],
    "shadow_api_testing": [
        "httpbin.org",
        "petstore.swagger.io",
    ],
}
