"""Event system — publish scan lifecycle events."""

import asyncio
import logging
from typing import Optional

from app.events.broker import broker

logger = logging.getLogger(__name__)


async def publish_webhook_event(
    event_type: str,
    scan_id: str,
    project_id: str,
    payload: Optional[dict] = None,
):
    """Publish a scan event to all registered webhook subscribers.

    Event types: scan.started, scan.completed, scan.failed,
                 finding.critical, finding.high
    """
    try:
        event_id = await broker.publish(
            event_type=event_type,
            payload=payload or {},
            scan_id=scan_id,
            project_id=project_id,
        )
        logger.debug(f"Published event {event_type} (id={event_id})")
        return event_id
    except Exception as e:
        logger.error(f"Failed to publish event {event_type}: {e}")
        return None


def register_webhook_subscriber(event_type: str, url: str, secret: str = ""):
    """Register a webhook subscriber (called from API or config)."""
    broker.register_subscriber(event_type, url, secret)
