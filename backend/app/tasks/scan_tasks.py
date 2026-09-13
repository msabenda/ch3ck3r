"""Async scan tasks for Celery."""
import asyncio
import logging
from uuid import UUID

from app.tasks import celery_app
from app.db.session import async_session_factory
from app.services.scan_service import ScanOrchestrator

logger = logging.getLogger(__name__)


@celery_app.task(bind=True, max_retries=3, default_retry_delay=10)
def run_scan(self, scan_id: str):
    """Execute a scan in a Celery worker."""
    logger.info(f"Starting scan task for scan_id={scan_id}")

    async def _execute():
        async with async_session_factory() as db:
            orchestrator = ScanOrchestrator(db)
            scan = await orchestrator.execute_scan(UUID(scan_id))
            return {
                "scan_id": str(scan.id),
                "status": scan.status.value,
                "total_findings": scan.total_findings,
                "risk_score": scan.risk_score,
            }

    try:
        loop = asyncio.new_event_loop()
        result = loop.run_until_complete(_execute())
        loop.close()
        logger.info(f"Scan {scan_id} completed: {result['status']}")
        return result
    except Exception as exc:
        logger.exception(f"Scan {scan_id} failed")
        raise self.retry(exc=exc)
