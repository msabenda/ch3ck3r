"""Report generation endpoints."""
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from typing import List
from uuid import UUID

from app.core.security import get_current_user
from app.db.session import get_db
from app.models import Scan, ScanStatus, Finding, Severity, Report, UserRole
from app.schemas import ReportResponse

router = APIRouter()


@router.get("/{scan_id}", response_model=List[ReportResponse])
async def list_reports(
    scan_id: str,
    db: AsyncSession = Depends(get_db),
    current_user=Depends(get_current_user),
):
    result = await db.execute(
        select(Report).where(Report.scan_id == UUID(scan_id))
        .order_by(Report.created_at.desc())
    )
    reports = result.scalars().all()
    return [
        ReportResponse(
            id=str(r.id), scan_id=str(r.scan_id), project_id=str(r.project_id),
            format=r.format, summary=r.summary, file_path=r.file_path,
            created_at=r.created_at,
        )
        for r in reports
    ]


@router.post("/{scan_id}/generate", response_model=ReportResponse)
async def generate_report(
    scan_id: str,
    report_format: str = "json",
    db: AsyncSession = Depends(get_db),
    current_user=Depends(get_current_user),
):
    """Generate a summary report from scan findings."""
    scan_result = await db.execute(select(Scan).where(Scan.id == UUID(scan_id)))
    scan = scan_result.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found")

    if scan.status != ScanStatus.COMPLETED:
        raise HTTPException(status_code=400, detail="Scan has not completed yet")

    # Gather findings
    findings_result = await db.execute(
        select(Finding).where(Finding.scan_id == UUID(scan_id))
    )
    findings = findings_result.scalars().all()

    summary = {
        "scan_id": str(scan.id),
        "scan_type": scan.scan_type,
        "target": scan.target,
        "risk_score": scan.risk_score,
        "total_findings": scan.total_findings,
        "severity_breakdown": {
            "critical": scan.critical_count,
            "high": scan.high_count,
            "medium": scan.medium_count,
            "low": scan.low_count,
            "info": scan.info_count,
        },
        "categories": {},
        "findings": [
            {
                "id": str(f.id),
                "title": f.title,
                "severity": f.severity.value,
                "category": f.category,
                "owasp_category": f.owasp_category,
                "endpoint": f.endpoint,
                "remediation": f.remediation,
                "cve_id": f.cve_id,
                "cwe_id": f.cwe_id,
            }
            for f in findings
        ],
        "generated_at": __import__("datetime").datetime.now().isoformat(),
    }

    # Build category summary
    for f in findings:
        cat = f.category
        if cat not in summary["categories"]:
            summary["categories"][cat] = {
                "count": 0,
                "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0,
            }
        s = f.severity.value
        summary["categories"][cat]["count"] += 1
        if s in summary["categories"][cat]:
            summary["categories"][cat][s] += 1

    # Save report record
    report = Report(
        scan_id=scan.id,
        project_id=scan.project_id,
        format=report_format,
        summary=summary,
    )
    db.add(report)
    await db.flush()
    await db.refresh(report)

    return ReportResponse(
        id=str(report.id), scan_id=str(report.scan_id),
        project_id=str(report.project_id), format=report.format,
        summary=report.summary, file_path=report.file_path,
        created_at=report.created_at,
    )
