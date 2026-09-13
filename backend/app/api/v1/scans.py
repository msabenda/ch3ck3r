"""Scan execution endpoints — single scan + full scan orchestrator."""

from fastapi import APIRouter, Depends, HTTPException, status, Query
from pydantic import BaseModel
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession
from typing import List, Optional
from uuid import UUID

from app.core.security import get_current_user, require_role
from app.db.session import get_db
from app.models import Scan, ScanStatus, UserRole, Finding, Severity
from app.schemas import ScanCreate, ScanResponse
from app.services.scan_service import ScanOrchestrator
from app.scanner.plugins import run_full_scan, get_available_scanners
from app.scanner.shadow_api_scanner import ShadowAPIScanner, PUBLIC_TEST_APIS
from app.metrics import active_scans

router = APIRouter()


# ─── Schemas ────────────────────────────────────────────────────

class FullScanRequest(BaseModel):
    """Request body for running a full scan across all scanners."""
    target: str
    project_id: str
    repo_url: Optional[str] = None


class FullScanResponse(BaseModel):
    """Response for a full scan, showing each sub-scan id."""
    scans: dict[str, str]  # scanner_name → scan_id
    message: str


class ScannerListResponse(BaseModel):
    scanners: list[dict]


# ─── Endpoints ──────────────────────────────────────────────────

@router.get("", response_model=List[ScanResponse])
async def list_scans(
    project_id: Optional[str] = None,
    status_filter: Optional[str] = None,
    scan_type: Optional[str] = None,
    limit: int = Query(default=50, le=200),
    offset: int = Query(default=0, ge=0),
    db: AsyncSession = Depends(get_db),
    current_user=Depends(get_current_user),
):
    """List scans with optional filters. Admins see all, others see own."""
    query = select(Scan)
    if current_user.role != UserRole.ADMIN.value:
        query = query.where(Scan.user_id == UUID(current_user.sub))
    if project_id:
        query = query.where(Scan.project_id == UUID(project_id))
    if status_filter:
        try:
            query = query.where(Scan.status == ScanStatus(status_filter))
        except ValueError:
            raise HTTPException(status_code=400, detail=f"Invalid status: {status_filter}")
    if scan_type:
        query = query.where(Scan.scan_type == scan_type)
    query = query.order_by(Scan.created_at.desc()).offset(offset).limit(limit)
    result = await db.execute(query)
    scans = result.scalars().all()
    return [_scan_to_response(s) for s in scans]


@router.get("/scanners")
async def list_scanners():
    """List available scanner plugins."""
    scanners = get_available_scanners()
    return {
        "scanners": [
            {
                "name": name,
                "type": "live_api" if name != "semgrep" else "sast",
            }
            for name in scanners
        ]
    }


@router.post("", response_model=ScanResponse, status_code=status.HTTP_201_CREATED)
async def create_scan(
    body: ScanCreate,
    db: AsyncSession = Depends(get_db),
    current_user=Depends(get_current_user),
):
    """Create a new scan."""
    orchestrator = ScanOrchestrator(db)
    try:
        scan = await orchestrator.create_scan(body, UUID(current_user.sub))
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    return _scan_to_response(scan)


@router.post("/full-scan", response_model=FullScanResponse)
async def full_scan(
    body: FullScanRequest,
    db: AsyncSession = Depends(get_db),
    current_user=Depends(get_current_user),
):
    """Run all applicable scanners against a target in one request.

    Creates individual Scan records per scanner and executes them.
    Semgrep uses repo_url for code scanning; live scanners hit the URL.
    """
    active_scans.inc()
    try:
        orchestrator = ScanOrchestrator(db)
        scan_ids = await orchestrator.execute_full_scan(
            target=body.target,
            user_id=UUID(current_user.sub),
            project_id=UUID(body.project_id),
            repo_url=body.repo_url,
        )

        scan_id_strs = {name: str(sid) for name, sid in scan_ids.items()}
        return FullScanResponse(
            scans=scan_id_strs,
            message=f"Full scan initiated with {len(scan_id_strs)} scanners: {', '.join(scan_id_strs.keys())}",
        )
    finally:
        active_scans.dec()


@router.get("/stats/overview")
async def scan_stats(
    db: AsyncSession = Depends(get_db),
    current_user=Depends(get_current_user),
):
    """Get aggregate scan statistics."""
    query = select(
        func.count().label("total_scans"),
        func.sum(Scan.total_findings).label("total_findings"),
        func.avg(Scan.risk_score).label("avg_risk_score"),
        func.sum(Scan.critical_count).label("critical_findings"),
    )
    if current_user.role != UserRole.ADMIN.value:
        query = query.where(Scan.user_id == UUID(current_user.sub))

    result = await db.execute(query)
    row = result.one()
    return {
        "total_scans": row.total_scans or 0,
        "total_findings": row.total_findings or 0,
        "critical_findings": row.critical_findings or 0,
        "avg_risk_score": round(float(row.avg_risk_score or 0), 1),
    }


# ─── Static routes before {scan_id} catch-all ─────────────────

@router.get('/test-apis')
async def list_test_apis():
    """Return public test APIs available for demo scanning (no auth required)."""
    return {
        "apis": PUBLIC_TEST_APIS,
        "count": len(PUBLIC_TEST_APIS),
        "tip": "Use these public APIs to test Ch3ck3r scanning capabilities without setup.",
    }


@router.post('/shadow-scan')
async def shadow_api_scan(
    target: str = Query(..., description="Target URL to scan for shadow APIs"),
    current_user=Depends(get_current_user),
):
    """Probe a target for shadow/undocumented API endpoints."""
    result = await ShadowAPIScanner.scan(target)
    return result


@router.post('/quick')
async def quick_scan(
    target: str = Query(..., description="Target URL to quickly scan"),
    current_user=Depends(get_current_user),
):
    """Quick scan — runs shadow API detection + standard scanner against a single URL."""
    # First run shadow API scan
    shadow_result = await ShadowAPIScanner.scan(target)

    # Then try framework detection
    import httpx
    framework_headers = {}
    try:
        async with httpx.AsyncClient(timeout=5, verify=False) as client:
            resp = await client.get(target.rstrip('/') + '/', headers={
                'User-Agent': 'Ch3ck3r-Scanner/2.0'
            })
            framework_headers = dict(resp.headers)
    except Exception:
        pass

    return {
        "target": target,
        "shadow_api_scan": shadow_result,
        "framework_headers": {
            k: v for k, v in framework_headers.items()
            if k.lower() in ('server', 'x-powered-by', 'x-frame-options', 'content-type')
        },
        "recommendation": (
            "High risk: Shadow APIs detected" if shadow_result['shadow_api_risk_score'] > 50
            else "Medium risk: Some undocumented endpoints" if shadow_result['shadow_api_risk_score'] > 20
            else "Low risk: No shadow APIs found"
        ),
    }


# ─── {scan_id} — catch-all routes (must be last) ──────────────

@router.get("/{scan_id}", response_model=ScanResponse)
async def get_scan(
    scan_id: str,
    db: AsyncSession = Depends(get_db),
    current_user=Depends(get_current_user),
):
    try:
        scan_uuid = UUID(scan_id)
    except (ValueError, AttributeError):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid scan ID: {scan_id}",
        )
    result = await db.execute(select(Scan).where(Scan.id == scan_uuid))
    scan = result.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found")
    if current_user.role != UserRole.ADMIN.value and str(scan.user_id) != current_user.sub:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Access denied")
    return _scan_to_response(scan)


@router.post("/{scan_id}/execute", response_model=ScanResponse)
async def execute_scan(
    scan_id: str,
    db: AsyncSession = Depends(get_db),
    current_user=Depends(get_current_user),
):
    """Execute a pending scan."""
    try:
        scan_uuid = UUID(scan_id)
    except (ValueError, AttributeError):
        raise HTTPException(400, detail=f"Invalid scan ID: {scan_id}")
    active_scans.inc()
    try:
        orchestrator = ScanOrchestrator(db)
        try:
            scan = await orchestrator.execute_scan(scan_uuid)
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e))
        return _scan_to_response(scan)
    finally:
        active_scans.dec()


# ─── Helpers ────────────────────────────────────────────────────

def _scan_to_response(s: Scan) -> ScanResponse:
    return ScanResponse(
        id=str(s.id),
        project_id=str(s.project_id),
        user_id=str(s.user_id),
        scan_type=s.scan_type,
        target=s.target,
        status=s.status.value,
        risk_score=s.risk_score,
        total_findings=s.total_findings,
        critical_count=s.critical_count,
        high_count=s.high_count,
        medium_count=s.medium_count,
        low_count=s.low_count,
        info_count=s.info_count,
        started_at=s.started_at,
        completed_at=s.completed_at,
        error_message=s.error_message,
        created_at=s.created_at,
    )
