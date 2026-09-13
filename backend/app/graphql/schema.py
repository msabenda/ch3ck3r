"""GraphQL API schema for Ch3ck3r using Strawberry."""

import strawberry
from strawberry.fastapi import GraphQLRouter
from strawberry.types import Info
from typing import Optional, List
from uuid import UUID
from datetime import datetime

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.session import get_db
from app.models import (
    Scan as ScanModel,
    Finding as FindingModel,
    Project as ProjectModel,
    User as UserModel,
    ScanStatus,
    Severity,
    UserRole,
)
from app.core.security import get_current_user


# ─── GraphQL Types ──────────────────────────────────────────────
# NOTE: Names MUST NOT collide with SQLAlchemy model class names,
# otherwise the DeclarativeBase registry throws:
# "Multiple classes found for path X in the registry of this declarative base"

@strawberry.type
class GQLUser:
    id: str
    email: str
    full_name: str
    role: str
    is_active: bool
    created_at: str

    @classmethod
    def from_model(cls, u: UserModel) -> "GQLUser":
        return cls(
            id=str(u.id),
            email=u.email,
            full_name=u.full_name or "",
            role=u.role.value if hasattr(u.role, 'value') else u.role,
            is_active=u.is_active,
            created_at=u.created_at.isoformat() if u.created_at else "",
        )


@strawberry.type
class GQLProject:
    id: str
    name: str
    description: str
    target_url: str
    repo_url: str
    created_at: str
    scan_count: int

    @classmethod
    def from_model(cls, p: ProjectModel, scan_count: int = 0) -> "GQLProject":
        return cls(
            id=str(p.id),
            name=p.name,
            description=p.description or "",
            target_url=p.target_url or "",
            repo_url=p.repo_url or "",
            created_at=p.created_at.isoformat() if p.created_at else "",
            scan_count=scan_count,
        )


@strawberry.type
class GQLFinding:
    id: str
    scan_id: str
    title: str
    description: str
    severity: str
    category: str
    owasp_category: str
    endpoint: str
    cve_id: str
    cwe_id: str
    created_at: str

    @classmethod
    def from_model(cls, f: FindingModel) -> "GQLFinding":
        return cls(
            id=str(f.id),
            scan_id=str(f.scan_id),
            title=f.title,
            description=f.description or "",
            severity=f.severity.value if hasattr(f.severity, 'value') else f.severity,
            category=f.category or "",
            owasp_category=f.owasp_category or "",
            endpoint=f.endpoint or "",
            cve_id=f.cve_id or "",
            cwe_id=f.cwe_id or "",
            created_at=f.created_at.isoformat() if f.created_at else "",
        )


@strawberry.type
class GQLScan:
    id: str
    project_id: str
    user_id: str
    scan_type: str
    target: str
    status: str
    risk_score: float
    total_findings: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    started_at: str
    completed_at: str
    created_at: str
    findings: List[GQLFinding]

    @classmethod
    def from_model(cls, s: ScanModel, findings: Optional[List[GQLFinding]] = None) -> "GQLScan":
        return cls(
            id=str(s.id),
            project_id=str(s.project_id),
            user_id=str(s.user_id),
            scan_type=s.scan_type,
            target=s.target,
            status=s.status.value if hasattr(s.status, 'value') else s.status,
            risk_score=s.risk_score or 0.0,
            total_findings=s.total_findings or 0,
            critical_count=s.critical_count or 0,
            high_count=s.high_count or 0,
            medium_count=s.medium_count or 0,
            low_count=s.low_count or 0,
            started_at=s.started_at.isoformat() if s.started_at else "",
            completed_at=s.completed_at.isoformat() if s.completed_at else "",
            created_at=s.created_at.isoformat() if s.created_at else "",
            findings=findings or [],
        )


@strawberry.type
class GQLScanStats:
    total_scans: int
    completed_scans: int
    failed_scans: int
    running_scans: int
    total_findings: int
    critical_findings: int
    average_risk_score: float


# ─── Queries ────────────────────────────────────────────────────

async def get_db_context(info: Info) -> AsyncSession:
    """Get database session from request context."""
    request = info.context["request"]
    async for session in get_db():
        return session


@strawberry.type
class Query:
    @strawberry.field
    async def me(self, info: Info) -> Optional[GQLUser]:
        """Get current authenticated user."""
        request = info.context["request"]
        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            return None
        token = auth_header.split(" ")[1]
        try:
            user_payload = await get_current_user(token=token)
        except Exception:
            return None

        db = await get_db_context(info)
        result = await db.execute(
            select(UserModel).where(UserModel.id == UUID(user_payload.sub))
        )
        user = result.scalar_one_or_none()
        return GQLUser.from_model(user) if user else None

    @strawberry.field
    async def projects(
        self,
        info: Info,
        limit: int = 20,
        offset: int = 0,
    ) -> List[GQLProject]:
        """List projects."""
        db = await get_db_context(info)
        result = await db.execute(
            select(ProjectModel).order_by(ProjectModel.created_at.desc()).offset(offset).limit(limit)
        )
        projects = result.scalars().all()
        result_list = []
        for p in projects:
            count_result = await db.execute(
                select(ScanModel).where(ScanModel.project_id == p.id)
            )
            scan_count = len(list(count_result.scalars().all()))
            result_list.append(GQLProject.from_model(p, scan_count))
        return result_list

    @strawberry.field
    async def scans(
        self,
        info: Info,
        project_id: Optional[str] = None,
        status: Optional[str] = None,
        scan_type: Optional[str] = None,
        limit: int = 20,
        offset: int = 0,
    ) -> List[GQLScan]:
        """List scans with optional filters. Includes full findings."""
        db = await get_db_context(info)
        query = select(ScanModel).order_by(ScanModel.created_at.desc())

        if project_id:
            query = query.where(ScanModel.project_id == UUID(project_id))
        if status:
            try:
                query = query.where(ScanModel.status == ScanStatus(status))
            except ValueError:
                pass
        if scan_type:
            query = query.where(ScanModel.scan_type == scan_type)

        query = query.offset(offset).limit(limit)
        result = await db.execute(query)
        scans = result.scalars().all()

        result_list = []
        for s in scans:
            findings_result = await db.execute(
                select(FindingModel).where(FindingModel.scan_id == s.id)
            )
            findings = [GQLFinding.from_model(f) for f in findings_result.scalars().all()]
            result_list.append(GQLScan.from_model(s, findings))
        return result_list

    @strawberry.field
    async def scan(self, info: Info, id: str) -> Optional[GQLScan]:
        """Get a single scan with all findings."""
        db = await get_db_context(info)
        result = await db.execute(select(ScanModel).where(ScanModel.id == UUID(id)))
        scan = result.scalar_one_or_none()
        if not scan:
            return None
        findings_result = await db.execute(
            select(FindingModel).where(FindingModel.scan_id == scan.id)
        )
        findings = [GQLFinding.from_model(f) for f in findings_result.scalars().all()]
        return GQLScan.from_model(scan, findings)

    @strawberry.field
    async def findings(
        self,
        info: Info,
        scan_id: Optional[str] = None,
        severity: Optional[str] = None,
        category: Optional[str] = None,
        limit: int = 50,
        offset: int = 0,
    ) -> List[GQLFinding]:
        """List findings with filters."""
        db = await get_db_context(info)
        query = select(FindingModel).order_by(FindingModel.created_at.desc())

        if scan_id:
            query = query.where(FindingModel.scan_id == UUID(scan_id))
        if severity:
            try:
                query = query.where(FindingModel.severity == Severity(severity))
            except ValueError:
                pass
        if category:
            query = query.where(FindingModel.category == category)

        query = query.offset(offset).limit(limit)
        result = await db.execute(query)
        return [GQLFinding.from_model(f) for f in result.scalars().all()]

    @strawberry.field
    async def scan_stats(self, info: Info) -> GQLScanStats:
        """Aggregate scan statistics."""
        db = await get_db_context(info)
        result = await db.execute(select(ScanModel))
        scans = list(result.scalars().all())

        total = len(scans)
        completed = sum(1 for s in scans if s.status == ScanStatus.COMPLETED)
        failed = sum(1 for s in scans if s.status == ScanStatus.FAILED)
        running = sum(1 for s in scans if s.status == ScanStatus.RUNNING)
        total_findings = sum(s.total_findings or 0 for s in scans)
        critical = sum(s.critical_count or 0 for s in scans)

        recent = sorted(scans, key=lambda s: s.created_at or datetime.min, reverse=True)[:10]
        risk_scores = [s.risk_score for s in recent if s.risk_score is not None]
        avg_risk = sum(risk_scores) / len(risk_scores) if risk_scores else 0

        return GQLScanStats(
            total_scans=total,
            completed_scans=completed,
            failed_scans=failed,
            running_scans=running,
            total_findings=total_findings,
            critical_findings=critical,
            average_risk_score=round(avg_risk, 2),
        )


# ─── Mutations ──────────────────────────────────────────────────

@strawberry.type
class Mutation:
    @strawberry.mutation
    async def create_scan(
        self,
        info: Info,
        project_id: str,
        scan_type: str,
        target: str,
    ) -> GQLScan:
        """Create and execute a scan via GraphQL."""
        db = await get_db_context(info)

        # Get user from token
        request = info.context["request"]
        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            raise Exception("Not authenticated")
        token = auth_header.split(" ")[1]
        try:
            user_payload = await get_current_user(token=token)
        except Exception as e:
            raise Exception(f"Authentication failed: {e}")

        from app.services.scan_service import ScanOrchestrator
        orchestrator = ScanOrchestrator(db)
        from app.schemas import ScanCreate
        scan_data = ScanCreate(
            project_id=project_id,
            scan_type=scan_type,
            target=target,
        )
        scan = await orchestrator.create_scan(scan_data, UUID(user_payload.sub))
        db.add(scan)
        await db.commit()

        # Execute
        scan = await orchestrator.execute_scan(scan.id)

        # Fetch findings
        findings_result = await db.execute(
            select(FindingModel).where(FindingModel.scan_id == scan.id)
        )
        findings = [GQLFinding.from_model(f) for f in findings_result.scalars().all()]
        return GQLScan.from_model(scan, findings)

    @strawberry.mutation
    async def create_project(
        self,
        info: Info,
        name: str,
        description: str = "",
        target_url: str = "",
        repo_url: str = "",
    ) -> GQLProject:
        """Create a new project."""
        db = await get_db_context(info)
        project = ProjectModel(
            name=name,
            description=description,
            target_url=target_url,
            repo_url=repo_url,
        )
        db.add(project)
        await db.commit()
        await db.refresh(project)
        return GQLProject.from_model(project)


# ─── Schema & Router ────────────────────────────────────────────

schema = strawberry.Schema(query=Query, mutation=Mutation)
graphql_router = GraphQLRouter(schema, path="/graphql")
