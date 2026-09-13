"""Ch3ck3r — FastAPI application factory."""

import asyncio
import logging
import sys
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError

from app.core.config import get_settings
from app.db.session import engine, async_session_factory

settings = get_settings()


def configure_logging():
    """Configure structured or standard logging."""
    log_level = getattr(logging, settings.LOG_LEVEL.upper(), logging.INFO)
    if settings.JSON_LOGS:
        from pythonjsonlogger import jsonlogger
        handler = logging.StreamHandler(sys.stdout)
        handler.setFormatter(jsonlogger.JsonFormatter())
        logging.basicConfig(level=log_level, handlers=[handler])
    else:
        logging.basicConfig(
            level=log_level,
            format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan — startup/shutdown."""
    configure_logging()
    logger = logging.getLogger(__name__)
    logger.info(f"Starting {settings.APP_NAME} v{settings.APP_VERSION}")
    logger.info(f"Debug mode: {settings.DEBUG}")
    logger.info(f"Rate limiting: {'enabled' if settings.RATE_LIMIT_ENABLED else 'disabled'}")

    # Log available scanners
    from app.scanner.plugins import get_available_scanners
    available = get_available_scanners()
    logger.info(f"Registered scanner plugins: {', '.join(available) or 'none'}")

    # Create tables on startup
    async with engine.begin() as conn:
        from app.db.session import Base
        await conn.run_sync(Base.metadata.create_all)
    logger.info("Database tables created")

    # Start webhook broker
    if settings.DEBUG or settings.WEBHOOK_ENABLED:
        from app.events.broker import broker
        asyncio.create_task(broker.start())
        logger.info("Webhook broker started")

    yield

    logger.info(f"Shutting down {settings.APP_NAME}")
    # Stop webhook broker
    try:
        from app.events.broker import broker
        await broker.stop()
    except Exception:
        pass
    await engine.dispose()


app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    description="API Misconfiguration Scanner — OWASP API Top 10 detection",
    lifespan=lifespan,
    docs_url="/docs" if settings.DEBUG else None,
    redoc_url="/redoc" if settings.DEBUG else None,
)


# ─── Middleware (order matters) ──────────────────────────────────

# 1. CORS — must be first
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins_list,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# 2. Prometheus metrics middleware (records request counts/durations)
from app.metrics import MetricsMiddleware
app.add_middleware(MetricsMiddleware)

# 3. Rate limiting middleware (Redis-backed)
from app.middleware.rate_limit import rate_limiter
rate_limiter.enabled = settings.RATE_LIMIT_ENABLED

@app.middleware("http")
async def rate_limit_middleware(request: Request, call_next):
    """Redis-backed rate limiting — skip on OPTIONS and preflight."""
    # Always allow OPTIONS preflight through without rate limiting
    if request.method == "OPTIONS":
        return await call_next(request)
    from app.middleware.rate_limit import rate_limit_middleware as _rl
    return await _rl(request, call_next)


# 4. Security headers middleware
@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    """Add security headers to every response."""
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "0"
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    response.headers["Cache-Control"] = "no-store"
    return response


# ─── Exception Handlers ─────────────────────────────────────────

@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    # Safe serialization of errors (exc.errors() can contain bytes)
    safe_errors = []
    for err in exc.errors():
        e = {}
        for k, v in err.items():
            if isinstance(v, bytes):
                e[k] = v.decode("utf-8", errors="replace")
            elif isinstance(v, tuple):
                e[k] = [str(x) if isinstance(x, bytes) else x for x in v]
            else:
                e[k] = v
        safe_errors.append(e)
    return JSONResponse(
        status_code=422,
        content={
            "detail": "Validation error",
            "errors": safe_errors,
        },
    )


@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    logger = logging.getLogger(__name__)
    logger.exception("Unhandled exception")
    detail = str(exc) if settings.DEBUG else "Internal server error"
    return JSONResponse(
        status_code=getattr(exc, "status_code", 500),
        content={"detail": detail},
    )


# ─── Multi-tenant middleware ────────────────────────────────────
from app.multitenant import setup_multitenancy
setup_multitenancy(app)


# ─── Routes ─────────────────────────────────────────────────────

from app.api.v1 import router as v1_router
app.include_router(v1_router, prefix="/api/v1")

# GraphQL endpoint
from app.graphql.schema import graphql_router
app.include_router(graphql_router, prefix="/graphql")

# Webhook subscriber management endpoints
from app.events.webhook_api import router as webhook_router
app.include_router(webhook_router, prefix="/api/v1/webhooks")

# Prometheus metrics endpoint (exposed by MetricsMiddleware at /metrics)


@app.get("/")
async def root():
    return {
        "app": settings.APP_NAME,
        "version": settings.APP_VERSION,
        "docs": "/docs" if settings.DEBUG else None,
        "graphql": "/graphql",
        "scanners": __import__("app.scanner.plugins", fromlist=["get_available_scanners"]).get_available_scanners(),
    }
