"""Webhook subscriber management API."""

from pydantic import BaseModel
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, status

from app.core.security import get_current_user, require_role
from app.models import UserRole
from app.events.broker import broker
from app.events import register_webhook_subscriber

router = APIRouter()


class WebhookSubscribeRequest(BaseModel):
    event_type: str
    url: str
    secret: Optional[str] = ""


class WebhookUnsubscribeRequest(BaseModel):
    event_type: str
    url: str


@router.post("/subscribe")
async def subscribe_webhook(
    body: WebhookSubscribeRequest,
    current_user=Depends(require_role(UserRole.ADMIN.value, UserRole.SCANNER.value)),
):
    """Subscribe a URL to receive webhook events for a specific event type."""
    if not body.url.startswith(("http://", "https://")):
        raise HTTPException(status_code=400, detail="Invalid webhook URL")

    valid_events = [
        "scan.started", "scan.completed", "scan.failed",
        "finding.critical", "finding.high",
        "*",  # wildcard — all events
    ]
    if body.event_type not in valid_events:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid event type. Valid: {', '.join(valid_events)}",
        )

    register_webhook_subscriber(body.event_type, body.url, body.secret or "")
    return {
        "status": "subscribed",
        "event_type": body.event_type,
        "url": body.url,
    }


@router.post("/unsubscribe")
async def unsubscribe_webhook(
    body: WebhookUnsubscribeRequest,
    current_user=Depends(require_role(UserRole.ADMIN.value)),
):
    """Unsubscribe a URL from an event type."""
    broker.remove_subscriber(body.event_type, body.url)
    return {"status": "unsubscribed", "event_type": body.event_type, "url": body.url}


@router.get("/subscribers")
async def list_subscribers(
    current_user=Depends(require_role(UserRole.ADMIN.value)),
):
    """List all registered webhook subscribers."""
    return {
        "subscribers": broker.list_subscribers(),
        "total": len(broker.list_subscribers()),
    }
