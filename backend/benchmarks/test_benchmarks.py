"""Benchmark tests for pytest-benchmark."""
import pytest
from benchmarks.benchmark import APIBenchmark


@pytest.mark.benchmark
@pytest.mark.asyncio
async def test_benchmark_health(benchmark):
    b = APIBenchmark()
    await b.authenticate()

    async def run():
        from benchmarks.benchmark import benchmark_health
        return await benchmark_health(b)

    result = benchmark(run)
    print(f"\n  Health: {result.throughput} ops/s | avg {result.avg_latency}ms | p95 {result.p95_latency}ms")


@pytest.mark.benchmark
@pytest.mark.asyncio
async def test_benchmark_scanners(benchmark):
    b = APIBenchmark()
    await b.authenticate()

    async def run():
        from benchmarks.benchmark import benchmark_scanners_list
        return await benchmark_scanners_list(b)

    result = benchmark(run)
    print(f"\n  Scanners: {result.throughput} ops/s | avg {result.avg_latency}ms | p95 {result.p95_latency}ms")
