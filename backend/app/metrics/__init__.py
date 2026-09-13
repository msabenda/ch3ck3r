"""Prometheus metrics for Ch3ck3r."""

import time
from prometheus_client import Counter, Histogram, Gauge, generate_latest, REGISTRY
from fastapi import FastAPI, Request, Response
from starlette.middleware.base import BaseHTTPMiddleware

# ─── Metrics ─────────────────────────────────────────────────────

# API request metrics
http_requests_total = Counter(
    "ch3ck3r_http_requests_total",
    "Total HTTP requests",
    ["method", "endpoint", "status"],
)

http_request_duration_seconds = Histogram(
    "ch3ck3r_http_request_duration_seconds",
    "HTTP request duration in seconds",
    ["method", "endpoint"],
    buckets=(0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10),
)

http_requests_in_progress = Gauge(
    "ch3ck3r_http_requests_in_progress",
    "Number of HTTP requests currently in progress",
    ["method"],
)

# Scan metrics
scans_total = Counter(
    "ch3ck3r_scans_total",
    "Total scans executed",
    ["scan_type", "status"],
)

scans_duration_seconds = Histogram(
    "ch3ck3r_scan_duration_seconds",
    "Scan duration in seconds",
    ["scan_type"],
    buckets=(1, 5, 10, 30, 60, 120, 300, 600, 1800, 3600),
)

findings_total = Counter(
    "ch3ck3r_findings_total",
    "Total findings by severity",
    ["severity", "category"],
)

active_scans = Gauge(
    "ch3ck3r_active_scans",
    "Number of scans currently running",
)

risk_score_gauge = Gauge(
    "ch3ck3r_risk_score",
    "Risk score of the most recent scan",
    ["scan_type"],
)

# Resource metrics
db_pool_size = Gauge("ch3ck3r_db_pool_size", "Database connection pool size")
db_pool_available = Gauge("ch3ck3r_db_pool_available", "Available database connections")

# User metrics
active_users = Gauge("ch3ck3r_active_users", "Number of active users")
projects_total = Gauge("ch3ck3r_projects_total", "Total number of projects")


class MetricsMiddleware(BaseHTTPMiddleware):
    """Middleware that records HTTP metrics."""

    async def dispatch(self, request: Request, call_next):
        method = request.method
        path = request.url.path

        # Normalize path for metrics (replace UUIDs and numbers)
        parts = path.split("/")
        normalized_parts = []
        for part in parts:
            if part and (
                len(part) == 36 and part.count("-") == 4  # UUID
                or part.isdigit()
            ):
                normalized_parts.append("{id}")
            else:
                normalized_parts.append(part)
        normalized_path = "/".join(normalized_parts) or "/"

        http_requests_in_progress.labels(method=method).inc()
        start = time.time()

        try:
            response = await call_next(request)
            status = str(response.status_code)
            return response
        except Exception as e:
            status = "500"
            raise
        finally:
            duration = time.time() - start
            http_requests_total.labels(method=method, endpoint=normalized_path, status=status).inc()
            http_request_duration_seconds.labels(method=method, endpoint=normalized_path).observe(duration)
            http_requests_in_progress.labels(method=method).dec()


def metrics_endpoint():
    """Return Prometheus metrics."""
    return Response(content=generate_latest(REGISTRY), media_type="text/plain")


def setup_metrics(app: FastAPI):
    """Configure Prometheus metrics for the application."""
    app.add_middleware(MetricsMiddleware)

    @app.get("/metrics")
    async def metrics():
        return metrics_endpoint()
