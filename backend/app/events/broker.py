"""Webhook event broker — dispatch scan events with retry logic and persistence."""

import asyncio
import json
import logging
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional
from uuid import uuid4

import httpx
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings

logger = logging.getLogger(__name__)
settings = get_settings()


@dataclass
class WebhookEvent:
    """An event to be dispatched to a webhook subscriber."""
    id: str = field(default_factory=lambda: str(uuid4()))
    event_type: str = ""
    scan_id: str = ""
    project_id: str = ""
    payload: dict = field(default_factory=dict)
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    retries: int = 0
    max_retries: int = 5
    next_retry_at: Optional[str] = None


# ── In-memory event store (persistent version would use Postgres) ──

_event_store: list[WebhookEvent] = []
_subscribers: dict[str, list[dict]] = {}  # event_type -> [{"url": str, "secret": str, "id": str}]


class WebhookBroker:
    """Event broker that dispatches webhook events with retry + backoff."""

    def __init__(self):
        self._client: Optional[httpx.AsyncClient] = None
        self._running = False
        self._worker_task: Optional[asyncio.Task] = None

    async def start(self):
        """Start the background worker for retries."""
        self._client = httpx.AsyncClient(timeout=30)
        self._running = True
        self._worker_task = asyncio.create_task(self._retry_worker())
        logger.info("Webhook broker started")

    async def stop(self):
        """Stop the background worker."""
        self._running = False
        if self._worker_task:
            self._worker_task.cancel()
            try:
                await self._worker_task
            except asyncio.CancelledError:
                pass
        if self._client:
            await self._client.aclose()
        logger.info("Webhook broker stopped")

    # ── Subscriber Management ──

    def register_subscriber(self, event_type: str, url: str, secret: str = "", subscriber_id: str = ""):
        """Register a webhook subscriber."""
        if event_type not in _subscribers:
            _subscribers[event_type] = []
        sub = {"url": url, "secret": secret, "id": subscriber_id or str(uuid4())}
        # Update if exists, else append
        existing = [s for s in _subscribers[event_type] if s["url"] == url]
        if existing:
            existing[0].update(sub)
        else:
            _subscribers[event_type].append(sub)
        logger.info(f"Registered webhook subscriber: {url} for {event_type}")

    def remove_subscriber(self, event_type: str, url: str):
        """Remove a webhook subscriber."""
        if event_type in _subscribers:
            _subscribers[event_type] = [s for s in _subscribers[event_type] if s["url"] != url]
            if not _subscribers[event_type]:
                del _subscribers[event_type]

    def list_subscribers(self) -> list[dict]:
        """List all subscribers grouped by event type."""
        result = []
        for event_type, subs in _subscribers.items():
            for s in subs:
                result.append({**s, "event_type": event_type})
        return result

    # ── Event Publishing ──

    async def publish(self, event_type: str, payload: dict, scan_id: str = "", project_id: str = ""):
        """Publish an event immediately to subscribers."""
        event = WebhookEvent(
            event_type=event_type,
            scan_id=scan_id,
            project_id=project_id,
            payload=payload,
        )
        _event_store.append(event)
        await self._dispatch(event)
        return event.id

    async def _dispatch(self, event: WebhookEvent):
        """Dispatch an event to all subscribers."""
        subscribers = _subscribers.get(event.event_type, [])
        if not subscribers:
            # Also try wildcard
            subscribers = _subscribers.get("*", [])

        if not subscribers:
            logger.debug(f"No subscribers for event type: {event.event_type}")
            return

        for sub in subscribers:
            try:
                await self._send_webhook(sub["url"], sub.get("secret", ""), event)
            except Exception as e:
                logger.warning(f"Webhook delivery failed to {sub['url']}: {e}")
                event.retries += 1
                if event.retries < event.max_retries:
                    # Exponential backoff: 10s, 30s, 90s, 270s, 810s
                    delay = 10 * (3 ** (event.retries - 1))
                    event.next_retry_at = datetime.now(timezone.utc).timestamp() + delay
                    logger.info(f"Scheduled retry {event.retries}/{event.max_retries} in {delay}s")

    async def _send_webhook(self, url: str, secret: str, event: WebhookEvent):
        """Send a single webhook request."""
        if not self._client:
            self._client = httpx.AsyncClient(timeout=30)

        headers = {
            "Content-Type": "application/json",
            "X-Ch3ck3r-Event": event.event_type,
            "X-Ch3ck3r-Event-Id": event.id,
            "X-Ch3ck3r-Delivery": datetime.now(timezone.utc).isoformat(),
        }
        if secret:
            import hmac
            import hashlib
            body = json.dumps(event.payload, default=str)
            signature = hmac.new(
                secret.encode(), body.encode(), hashlib.sha256
            ).hexdigest()
            headers["X-Ch3ck3r-Signature"] = f"sha256={signature}"

        response = await self._client.post(url, json=event.payload, headers=headers)
        response.raise_for_status()
        logger.info(f"Webhook delivered to {url} (event: {event.event_type}, status: {response.status_code})")

    # ── Retry Worker ──

    async def _retry_worker(self):
        """Background worker that retries failed events."""
        while self._running:
            try:
                now = time.time()
                retry_events = [
                    e for e in _event_store
                    if e.next_retry_at and float(e.next_retry_at) <= now and e.retries < e.max_retries
                ]
                for event in retry_events:
                    event.next_retry_at = None
                    await self._dispatch(event)
            except Exception as e:
                logger.error(f"Retry worker error: {e}")
            await asyncio.sleep(5)


# Global broker instance
broker = WebhookBroker()
