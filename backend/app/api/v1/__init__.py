"""API v1 router — mounts all endpoint modules."""
from fastapi import APIRouter

from app.api.v1.auth import router as auth_router
from app.api.v1.users import router as users_router
from app.api.v1.projects import router as projects_router
from app.api.v1.scans import router as scans_router
from app.api.v1.findings import router as findings_router
from app.api.v1.reports import router as reports_router
from app.api.v1.health import router as health_router
from app.api.v1.ws import router as ws_router
from app.api.v1.diff import router as diff_router
from app.api.v1.github import router as github_router
from app.api.v1.imports import router as imports_router
from app.api.v1.integrations import router as integrations_router

router = APIRouter()

router.include_router(health_router, prefix="/health", tags=["Health"])
router.include_router(auth_router, prefix="/auth", tags=["Authentication"])
router.include_router(users_router, prefix="/users", tags=["Users"])
router.include_router(projects_router, prefix="/projects", tags=["Projects"])
router.include_router(scans_router, prefix="/scans", tags=["Scans"])
router.include_router(findings_router, prefix="/findings", tags=["Findings"])
router.include_router(reports_router, prefix="/reports", tags=["Reports"])
router.include_router(diff_router, prefix="/scans", tags=["Scans"])
router.include_router(github_router, prefix="/github", tags=["GitHub"])
router.include_router(imports_router, prefix="/imports", tags=["Imports"])
router.include_router(integrations_router, prefix="/integrations", tags=["Integrations"])
