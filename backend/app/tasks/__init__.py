"""Default task helpers and Celery worker config."""
# Placeholder — Celery worker will be wired in next phase

from celery import Celery
from app.core.config import get_settings

settings = get_settings()

celery_app = Celery(
    "ch3ck3r",
    broker=settings.CELERY_BROKER_URL,
    backend=settings.CELERY_RESULT_BACKEND,
    include=["app.tasks.scan_tasks"],
)

celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    task_track_started=True,
    task_time_limit=settings.SCAN_TIMEOUT_SECONDS + 60,
    task_soft_time_limit=settings.SCAN_TIMEOUT_SECONDS,
    worker_max_tasks_per_child=50,
)
