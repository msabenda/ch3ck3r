"""Performance benchmarks for Ch3ck3r API.

Run with: python -m pytest benchmarks/ -v --benchmark-only
Or: python benchmarks/benchmark.py for standalone
"""

import asyncio
import json
import time
import statistics
from typing import Callable, Any
from dataclasses import dataclass, field

import httpx


@dataclass
class BenchmarkResult:
    """Results from a single benchmark run."""
    name: str
    operations: int
    concurrency: int
    total_time: float
    avg_latency: float
    p50_latency: float
    p95_latency: float
    p99_latency: float
    throughput: float  # ops/sec
    errors: int = 0


class APIBenchmark:
    """Benchmark runner for HTTP APIs."""

    def __init__(self, base_url: str = "http://localhost:8000"):
        self.base_url = base_url
        self.token: str = ""

    async def authenticate(self):
        """Register and login to get a token."""
        async with httpx.AsyncClient(base_url=self.base_url) as client:
            email = f"bench-{int(time.time())}@ch3ck3r.io"
            await client.post("/api/v1/auth/register", json={
                "email": email,
                "password": "BenchP@ss123",
                "full_name": "Benchmark User",
            })
            resp = await client.post(
                "/api/v1/auth/login",
                data={"username": email, "password": "BenchP@ss123"},
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )
            self.token = resp.json()["access_token"]

    @property
    def headers(self):
        return {"Authorization": f"Bearer {self.token}"}

    async def run_single(
        self,
        name: str,
        operation: Callable[[httpx.AsyncClient], Any],
        operations: int = 100,
        concurrency: int = 10,
    ) -> BenchmarkResult:
        """Run a benchmark with concurrent requests."""
        latencies = []
        errors = 0
        start = time.time()

        async def worker(sem: asyncio.Semaphore, results: list):
            nonlocal errors
            async with httpx.AsyncClient(base_url=self.base_url, timeout=30) as client:
                for _ in range(operations // concurrency):
                    async with sem:
                        op_start = time.time()
                        try:
                            await operation(client)
                            latencies.append((time.time() - op_start) * 1000)
                        except Exception:
                            errors += 1

        sem = asyncio.Semaphore(concurrency)
        tasks = [worker(sem, []) for _ in range(concurrency)]
        await asyncio.gather(*tasks)

        total_time = time.time() - start
        sorted_lats = sorted(latencies)

        return BenchmarkResult(
            name=name,
            operations=operations,
            concurrency=concurrency,
            total_time=round(total_time, 3),
            avg_latency=round(statistics.mean(latencies), 2) if latencies else 0,
            p50_latency=round(sorted_lats[len(sorted_lats) // 2], 2) if sorted_lats else 0,
            p95_latency=round(sorted_lats[int(len(sorted_lats) * 0.95)], 2) if sorted_lats else 0,
            p99_latency=round(sorted_lats[int(len(sorted_lats) * 0.99)], 2) if sorted_lats else 0,
            throughput=round(operations / total_time, 2),
            errors=errors,
        )


# ── Specific Benchmarks ─────────────────────────────────────────

async def benchmark_health(b: APIBenchmark) -> BenchmarkResult:
    return await b.run_single(
        "GET /health/live",
        lambda c: c.get("/api/v1/health/live"),
        operations=500,
        concurrency=50,
    )


async def benchmark_auth_register(b: APIBenchmark) -> BenchmarkResult:
    counter = 0
    async def register(client):
        nonlocal counter
        counter += 1
        await client.post("/api/v1/auth/register", json={
            "email": f"bench-bulk-{int(time.time())}-{counter}@ch3ck3r.io",
            "password": "BenchP@ss123",
            "full_name": "Bulk User",
        })
    # Lower counts to avoid DB bloat
    return await b.run_single(
        "POST /auth/register",
        register,
        operations=20,
        concurrency=5,
    )


async def benchmark_auth_login(b: APIBenchmark) -> BenchmarkResult:
    # Pre-register a user
    async with httpx.AsyncClient(base_url=b.base_url) as client:
        await client.post("/api/v1/auth/register", json={
            "email": "bench-login-target@ch3ck3r.io",
            "password": "BenchP@ss123",
            "full_name": "Login Target",
        })
    return await b.run_single(
        "POST /auth/login",
        lambda c: c.post(
            "/api/v1/auth/login",
            data={"username": "bench-login-target@ch3ck3r.io", "password": "BenchP@ss123"},
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        ),
        operations=100,
        concurrency=20,
    )


async def benchmark_projects_crud(b: APIBenchmark) -> BenchmarkResult:
    return await b.run_single(
        "GET /projects (list)",
        lambda c: c.get("/api/v1/projects", headers=b.headers),
        operations=200,
        concurrency=20,
    )


async def benchmark_scans_list(b: APIBenchmark) -> BenchmarkResult:
    return await b.run_single(
        "GET /scans (list)",
        lambda c: c.get("/api/v1/scans", headers=b.headers),
        operations=200,
        concurrency=20,
    )


async def benchmark_scans_stats(b: APIBenchmark) -> BenchmarkResult:
    return await b.run_single(
        "GET /scans/stats/overview",
        lambda c: c.get("/api/v1/scans/stats/overview", headers=b.headers),
        operations=200,
        concurrency=20,
    )


async def benchmark_scanners_list(b: APIBenchmark) -> BenchmarkResult:
    return await b.run_single(
        "GET /scans/scanners",
        lambda c: c.get("/api/v1/scans/scanners", headers=b.headers),
        operations=500,
        concurrency=50,
    )


async def benchmark_findings_list(b: APIBenchmark) -> BenchmarkResult:
    return await b.run_single(
        "GET /findings (list)",
        lambda c: c.get("/api/v1/findings?limit=20", headers=b.headers),
        operations=200,
        concurrency=20,
    )


async def benchmark_full_stacked(b: APIBenchmark) -> BenchmarkResult:
    """Simulate a real user flow: list projects, then scans, then findings."""
    async def full_flow(client):
        await client.get("/api/v1/projects", headers=b.headers)
        await client.get("/api/v1/scans?limit=10", headers=b.headers)
        await client.get("/api/v1/findings?limit=10", headers=b.headers)
        await client.get("/api/v1/scans/stats/overview", headers=b.headers)
        await client.get("/api/v1/scans/scanners", headers=b.headers)

    return await b.run_single(
        "Full stacked (5 reqs/user)",
        full_flow,
        operations=50,
        concurrency=10,
    )


# ── Main ────────────────────────────────────────────────────────

def print_report(results: list[BenchmarkResult]):
    """Pretty-print benchmark results."""
    separator = f"{'─' * 90}"
    print(f"\n{'=' * 90}")
    print(f"  Ch3ck3r API Benchmark Report")
    print(f"{'=' * 90}")
    print(f"{'Endpoint':<36} {'Ops':>5} {'Time(s)':>8} {'Avg(ms)':>8} {'P50(ms)':>8} {'P95(ms)':>8} {'P99(ms)':>8} {'Ops/s':>8} {'Err':>4}")
    print(separator)

    for r in results:
        print(
            f"{r.name:<36} {r.operations:>5} {r.total_time:>8.2f} {r.avg_latency:>8.2f} {r.p50_latency:>8.2f} "
            f"{r.p95_latency:>8.2f} {r.p99_latency:>8.2f} {r.throughput:>8.2f} {r.errors:>4}"
        )

    print(separator)
    totals = f"{'TOTAL':<36} {sum(r.operations for r in results):>5} {'':>8} {'':>8} {'':>8} {'':>8} {'':>8} {'':>8} {sum(r.errors for r in results):>4}"
    print(totals)
    print(f"{'=' * 90}\n")


async def run_all(base_url: str = "http://localhost:8000"):
    """Run all benchmarks."""
    b = APIBenchmark(base_url)

    print(f"\nAuthenticating to {base_url}...")
    await b.authenticate()
    print("✓ Authenticated\n")

    benchmarks = [
        ("Health Check", benchmark_health),
        ("Auth Register", benchmark_auth_register),
        ("Auth Login", benchmark_auth_login),
        ("Projects List", benchmark_projects_crud),
        ("Scans List", benchmark_scans_list),
        ("Scans Stats", benchmark_scans_stats),
        ("Scanners List", benchmark_scanners_list),
        ("Findings List", benchmark_findings_list),
        ("Full Stacked Flow", benchmark_full_stacked),
    ]

    results = []
    for name, bench_fn in benchmarks:
        print(f"  Running: {name}...")
        try:
            result = await bench_fn(b)
            results.append(result)
            print(f"    ✓ {result.operations} ops in {result.total_time}s ({result.throughput} ops/s)")
        except Exception as e:
            print(f"    ✗ Failed: {e}")

    print_report(results)
    return results


if __name__ == "__main__":
    import sys
    url = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:8000"
    asyncio.run(run_all(url))
