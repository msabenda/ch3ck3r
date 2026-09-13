"""Multi-tenant middleware — isolates data by organization/team."""

import logging
from typing import Optional
from uuid import UUID

from fastapi import FastAPI, Request, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.core.security import get_current_user
from app.models import User, UserRole, Project, Scan, Finding
from app.schemas.auth import TokenPayload

logger = logging.getLogger(__name__)
settings = get_settings()


class TenantContext:
    """Holds tenant information for the current request."""

    def __init__(self):
        self.tenant_id: Optional[str] = None
        self.organization_id: Optional[str] = None
        self.role: Optional[str] = None

    def is_multi_tenant(self) -> bool:
        return self.tenant_id is not None

    @property
    def filter_clause(self):
        """Returns SQLAlchemy filter clause for multi-tenant isolation."""
        if not self.tenant_id:
            return True  # No filtering in single-tenant mode
        # All models must have organization_id column
        return True  # Placeholder — actual implementation uses ORG_ID


# Global tenant context (thread-safe via contextvars in production)
tenant_context = TenantContext()


def is_multitenant() -> bool:
    """Check if multi-tenancy is enabled globally."""
    return settings.MULTI_TENANT_ENABLED or False


async def tenant_middleware(request: Request, call_next):
    """Middleware that enforces multi-tenant data isolation.

    Expects X-Organization-ID header or derives tenant from JWT claims.
    """
    if not is_multitenant():
        return await call_next(request)

    # Extract tenant from header or JWT
    org_id = request.headers.get("X-Organization-ID", "")

    # Try to get tenant from JWT if not in header
    if not org_id:
        auth_header = request.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            try:
                user = await get_current_user(token=auth_header.split(" ")[1])
                if hasattr(user, 'organization_id') and user.organization_id:
                    org_id = str(user.organization_id)
            except Exception:
                pass

    if not org_id:
        return await call_next(request)  # No tenant — pass through (admin may see all)

    # Set tenant context for the request
    old_org_id = tenant_context.organization_id
    old_tenant_id = tenant_context.tenant_id
    tenant_context.organization_id = org_id
    tenant_context.tenant_id = org_id

    try:
        response = await call_next(request)
        return response
    finally:
        # Restore (should be None but clean up regardless)
        tenant_context.organization_id = old_org_id
        tenant_context.tenant_id = old_tenant_id


def apply_tenant_filter(query, model_class):
    """Apply organization filter to a query if multi-tenant mode is active."""
    if not is_multitenant() or not tenant_context.organization_id:
        return query

    org_column = getattr(model_class, "organization_id", None)
    if org_column is None:
        return query

    return query.where(org_column == UUID(tenant_context.organization_id))


def setup_multitenancy(app: FastAPI):
    """Apply multi-tenancy middleware to the FastAPI app."""
    if settings.MULTI_TENANT_ENABLED:
        app.middleware("http")(tenant_middleware)
        logger.info("Multi-tenancy enabled")
