"""Redis-backed rate limiting middleware for FastAPI."""

import asyncio
import logging
import time
from typing import Optional

import redis.asyncio as redis
from fastapi import FastAPI, Request, HTTPException, status
from fastapi.responses import JSONResponse

from app.core.config import get_settings

logger = logging.getLogger(__name__)
settings = get_settings()


class RateLimiter:
    """Sliding window rate limiter using Redis sorted sets."""

    def __init__(self):
        self.redis_pool: Optional[redis.Redis] = None
        self.enabled = settings.RATE_LIMIT_ENABLED

    async def _get_redis(self) -> Optional[redis.Redis]:
        if self.redis_pool is None:
            try:
                self.redis_pool = redis.from_url(
                    settings.REDIS_URL,
                    socket_connect_timeout=2,
                    socket_keepalive=True,
                    decode_responses=True,
                )
                await self.redis_pool.ping()
            except Exception as e:
                logger.warning(f"Rate limiter Redis unavailable: {e}")
                self.redis_pool = None  # Reset so we retry next time
                return None
        return self.redis_pool

    async def check_rate_limit(
        self, key: str, max_requests: int = 100, window_seconds: int = 60
    ) -> bool:
        """Check if request is within rate limit. Returns True if allowed."""
        if not self.enabled:
            return True

        r = await self._get_redis()
        if r is None:
            return True  # Allow if Redis is down (fail open)

        try:
            now = time.time()
            window_start = now - window_seconds

            # Remove old entries
            await r.zremrangebyscore(key, 0, window_start)

            # Count current entries
            count = await r.zcard(key)

            if count >= max_requests:
                return False

            # Add current request
            await r.zadd(key, {str(now): now})
            await r.expire(key, window_seconds)
            return True

        except Exception as e:
            logger.warning(f"Rate limit check failed: {e}")
            return True  # Fail open

    async def get_remaining(self, key: str, max_requests: int = 100) -> int:
        """Get remaining requests in current window."""
        r = await self._get_redis()
        if r is None:
            return max_requests

        try:
            now = time.time()
            window_start = now - settings.RATE_LIMIT_WINDOW_SECONDS
            await r.zremrangebyscore(key, 0, window_start)
            count = await r.zcard(key)
            return max(0, max_requests - count)
        except Exception:
            return max_requests

    async def get_reset_time(self, key: str, window_seconds: int = 60) -> int:
        """Get seconds until rate limit resets."""
        r = await self._get_redis()
        if r is None:
            return 0
        try:
            ttl = await r.ttl(key)
            return max(0, ttl)
        except Exception:
            return 0


# Global rate limiter instance
rate_limiter = RateLimiter()


async def rate_limit_middleware(request: Request, call_next):
    """FastAPI middleware for rate limiting."""
    if not rate_limiter.enabled:
        return await call_next(request)

    # Skip rate limiting for health checks and docs
    skip_paths = ("/api/v1/health", "/docs", "/redoc", "/openapi.json")
    if any(request.url.path.startswith(p) for p in skip_paths):
        return await call_next(request)

    # Build key: user IP or token
    forwarded = request.headers.get("X-Forwarded-For", "")
    client_ip = forwarded.split(",")[0].strip() if forwarded else request.client.host if request.client else "unknown"
    auth_header = request.headers.get("Authorization", "")
    if auth_header.startswith("Bearer "):
        # Use token hash as key for authenticated users
        import hashlib
        token_hash = hashlib.sha256(auth_header.encode()).hexdigest()[:16]
        key = f"rl:token:{token_hash}"
    else:
        key = f"rl:ip:{client_ip}"

    allowed = await rate_limiter.check_rate_limit(
        key,
        max_requests=settings.RATE_LIMIT_REQUESTS,
        window_seconds=settings.RATE_LIMIT_WINDOW_SECONDS,
    )

    if not allowed:
        remaining = await rate_limiter.get_remaining(key, settings.RATE_LIMIT_REQUESTS)
        reset_time = await rate_limiter.get_reset_time(key, settings.RATE_LIMIT_WINDOW_SECONDS)

        return JSONResponse(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            content={
                "detail": "Rate limit exceeded. Try again later.",
                "retry_after_seconds": reset_time,
            },
            headers={
                "Retry-After": str(reset_time),
                "X-RateLimit-Limit": str(settings.RATE_LIMIT_REQUESTS),
                "X-RateLimit-Remaining": str(remaining),
                "X-RateLimit-Reset": str(int(time.time()) + reset_time),
            },
        )

    response = await call_next(request)
    return response


def setup_rate_limiting(app: FastAPI):
    """Apply rate limiting middleware to the FastAPI app."""
    app.middleware("http")(rate_limit_middleware)
    logger.info("Rate limiting enabled")
