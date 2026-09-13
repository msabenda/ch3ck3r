"""Findings endpoints."""
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from typing import List, Optional
from uuid import UUID

from app.core.security import get_current_user
from app.db.session import get_db
from app.models import Finding, Severity, UserRole, Scan
from app.schemas import FindingResponse, FindingUpdate

router = APIRouter()


@router.get("", response_model=List[FindingResponse])
async def list_findings(
    scan_id: Optional[str] = None,
    severity: Optional[str] = None,
    category: Optional[str] = None,
    limit: int = 100,
    db: AsyncSession = Depends(get_db),
    current_user=Depends(get_current_user),
):
    query = select(Finding)
    if scan_id:
        query = query.where(Finding.scan_id == UUID(scan_id))
    if severity:
        try:
            query = query.where(Finding.severity == Severity(severity))
        except ValueError:
            raise HTTPException(status_code=400, detail=f"Invalid severity: {severity}")
    if category:
        query = query.where(Finding.category == category)
    query = query.order_by(
        Finding.severity.asc(),  # critical first (enum order)
        Finding.created_at.desc(),
    ).limit(limit)
    result = await db.execute(query)
    findings = result.scalars().all()
    return [
        FindingResponse(
            id=str(f.id), scan_id=str(f.scan_id), title=f.title,
            description=f.description, severity=f.severity.value, category=f.category,
            owasp_category=f.owasp_category, endpoint=f.endpoint,
            evidence=f.evidence, remediation=f.remediation,
            cve_id=f.cve_id, cwe_id=f.cwe_id,
            false_positive=f.false_positive, created_at=f.created_at,
        )
        for f in findings
    ]


@router.patch("/{finding_id}", response_model=FindingResponse)
async def update_finding(
    finding_id: str,
    body: FindingUpdate,
    db: AsyncSession = Depends(get_db),
    current_user=Depends(get_current_user),
):
    result = await db.execute(select(Finding).where(Finding.id == UUID(finding_id)))
    finding = result.scalar_one_or_none()
    if not finding:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Finding not found")

    if body.false_positive is not None:
        finding.false_positive = body.false_positive

    await db.flush()
    await db.refresh(finding)
    return FindingResponse(
        id=str(finding.id), scan_id=str(finding.scan_id), title=finding.title,
        description=finding.description, severity=finding.severity.value,
        category=finding.category, owasp_category=finding.owasp_category,
        endpoint=finding.endpoint, evidence=finding.evidence,
        remediation=finding.remediation, cve_id=finding.cve_id,
        cwe_id=finding.cwe_id, false_positive=finding.false_positive,
        created_at=finding.created_at,
    )
