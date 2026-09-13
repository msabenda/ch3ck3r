"""Scan diff API endpoints — compare scans over time."""
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from pydantic import BaseModel
from typing import Optional
from uuid import UUID

from app.core.security import get_current_user
from app.db.session import get_db
from app.scanner.diff.engine import ScanDiffEngine, ScanDiff, DiffEntry
from app.scanner.chains.orchestrator import chain_orchestrator, ChainConfig

router = APIRouter()


class DiffResponse(BaseModel):
    base_scan_id: str
    compare_scan_id: str
    target: str
    new_findings: list[dict]
    fixed_findings: list[dict]
    recurring_findings: list[dict]
    severity_changes: list[dict]
    risk_score_change: Optional[float]
    total_changes: int
    net_risk_change: str


@router.get("/diff/{scan_id_a}/{scan_id_b}")
async def compare_scans(
    scan_id_a: str,
    scan_id_b: str,
    db: AsyncSession = Depends(get_db),
    current_user=Depends(get_current_user),
):
    """Compare findings between two scans."""
    engine = ScanDiffEngine(db)
    diff = await engine.diff(UUID(scan_id_a), UUID(scan_id_b))
    if not diff:
        raise HTTPException(status_code=404, detail="Could not compute diff")

    return _diff_to_response(diff)


@router.get("/diff/latest/{project_id}/{scan_type}")
async def compare_latest_scans(
    project_id: str,
    scan_type: str,
    db: AsyncSession = Depends(get_db),
    current_user=Depends(get_current_user),
):
    """Compare the latest two scans of the same type in a project."""
    engine = ScanDiffEngine(db)
    diff = await engine.diff_latest(UUID(project_id), scan_type)
    if not diff:
        raise HTTPException(status_code=404, detail="Need at least 2 completed scans to diff")

    return _diff_to_response(diff)


@router.get("/chains")
async def list_chains():
    """List available scan chains."""
    return {"chains": chain_orchestrator.get_available_chains()}


@router.post("/chains/{chain_name}/run")
async def run_chain(
    chain_name: str,
    target: str,
    project_id: str,
    repo_url: Optional[str] = None,
    current_user=Depends(get_current_user),
):
    """Execute a scan chain (multi-scanner orchestration)."""
    try:
        results = await chain_orchestrator.run_chain(chain_name, target, repo_url)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    return {
        "chain": chain_name,
        "target": target,
        "results": {
            name: {
                "status": r.status,
                "risk_score": r.risk_score,
                "finding_count": len(r.findings),
                "error": r.error_message,
            }
            for name, r in results.items()
        },
    }


def _diff_to_response(diff: ScanDiff) -> DiffResponse:
    def entry_to_dict(e: DiffEntry) -> dict:
        return {
            "type": e.type,
            "title": e.title,
            "old_severity": e.old_severity,
            "new_severity": e.new_severity,
            "severity_from": e.old_severity,
            "severity_to": e.new_severity,
            "endpoint": e.endpoint,
            "cve_id": e.cve_id,
        }

    return DiffResponse(
        base_scan_id=diff.base_scan_id,
        compare_scan_id=diff.compare_scan_id,
        target=diff.target,
        new_findings=[entry_to_dict(e) for e in diff.new_findings],
        fixed_findings=[entry_to_dict(e) for e in diff.fixed_findings],
        recurring_findings=[entry_to_dict(e) for e in diff.recurring_findings],
        severity_changes=[entry_to_dict(e) for e in diff.severity_changes],
        risk_score_change=diff.risk_score_change,
        total_changes=diff.total_changes,
        net_risk_change=diff.net_risk_change,
    )
