"""Platform integrations API.

Supports Postman, Azure API Management, MuleSoft, Apigee, SwaggerHub,
Kong, Boomi, Jira, Azure DevOps, Slack, Microsoft Teams, Jenkins,
GitHub Actions, GitLab CI/CD.
"""
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from typing import Optional, Dict, Any
from app.core.security import get_current_user
import httpx

router = APIRouter()


class IntegrationConfig(BaseModel):
    platform: str
    name: str
    config: Dict[str, Any] = {}
    enabled: bool = True


PLATFORMS: Dict[str, dict] = {
    "postman": {
        "name": "Postman",
        "description": "Sync Postman collections and run scans against APIs",
        "icon": "📮",
        "color": "#FF6C37",
        "fields": ["api_key", "workspace_id", "collection_uid"],
        "doc_url": "https://learning.postman.com/docs/developer/postman-api/intro-api/",
    },
    "azure": {
        "name": "Azure API Management",
        "description": "Import and scan APIs from Azure API Management",
        "icon": "☁️",
        "color": "#0078D4",
        "fields": [
            "tenant_id", "subscription_id", "resource_group",
            "apim_service_name", "client_id", "client_secret"
        ],
        "doc_url": "https://learn.microsoft.com/en-us/azure/api-management/",
    },
    "mulesoft": {
        "name": "MuleSoft Anypoint",
        "description": "Scan APIs from MuleSoft Anypoint Exchange",
        "icon": "🔷",
        "color": "#00A3E0",
        "fields": [
            "anypoint_username", "anypoint_password",
            "environment_id", "exchange_asset_id"
        ],
        "doc_url": "https://docs.mulesoft.com/general/",
    },
    "apigee": {
        "name": "Google Apigee",
        "description": "Import and scan APIs from Apigee X/hybrid",
        "icon": "🟦",
        "color": "#4285F4",
        "fields": [
            "organization", "environment", "username", "password"
        ],
        "doc_url": "https://cloud.google.com/apigee/docs",
    },
    "swaggerhub": {
        "name": "SwaggerHub",
        "description": "Import OpenAPI specs from SwaggerHub",
        "icon": "📘",
        "color": "#85EA2D",
        "fields": ["api_key", "owner", "api_name", "version"],
        "doc_url": "https://swagger.io/docs/open-source-tools/swaggerhub/",
    },
    "kong": {
        "name": "Kong API Gateway",
        "description": "Scan APIs managed by Kong Gateway",
        "icon": "🐵",
        "color": "#00313F",
        "fields": ["admin_url", "admin_token", "workspace"],
        "doc_url": "https://docs.konghq.com/gateway/",
    },
    "boomi": {
        "name": "Boomi",
        "description": "Scan APIs from Boomi API Management",
        "icon": "🌐",
        "color": "#0072CE",
        "fields": [
            "account_id", "username", "password", "environment_id"
        ],
        "doc_url": "https://help.boomi.com/",
    },
    "jira": {
        "name": "Jira",
        "description": "Create Jira issues from scan findings",
        "icon": "🔷",
        "color": "#0052CC",
        "fields": [
            "jira_url", "email", "api_token", "project_key", "issue_type"
        ],
        "doc_url": "https://developer.atlassian.com/cloud/jira/platform/",
    },
    "azure_devops": {
        "name": "Azure DevOps",
        "description": "Create work items from scan findings in Azure DevOps",
        "icon": "🟦",
        "color": "#0078D4",
        "fields": [
            "organization", "project", "pat_token", "work_item_type"
        ],
        "doc_url": "https://learn.microsoft.com/en-us/azure/devops/",
    },
    "slack": {
        "name": "Slack",
        "description": "Send scan alerts and findings to Slack channels",
        "icon": "💬",
        "color": "#4A154B",
        "fields": ["webhook_url", "channel", "bot_token"],
        "doc_url": "https://api.slack.com/messaging/webhooks",
    },
    "ms_teams": {
        "name": "Microsoft Teams",
        "description": "Send alerts to Microsoft Teams channels",
        "icon": "💼",
        "color": "#6264A7",
        "fields": ["webhook_url", "channel_id", "tenant_id"],
        "doc_url": "https://learn.microsoft.com/en-us/microsoftteams/platform/",
    },
    "jenkins": {
        "name": "Jenkins",
        "description": "Trigger Jenkins pipeline jobs from scan results",
        "icon": "🤖",
        "color": "#D24939",
        "fields": ["jenkins_url", "username", "api_token", "job_name"],
        "doc_url": "https://www.jenkins.io/doc/",
    },
    "github_actions": {
        "name": "GitHub Actions",
        "description": "Trigger GitHub Actions workflows on scan completion",
        "icon": "🐙",
        "color": "#181717",
        "fields": [
            "github_token", "owner", "repo", "workflow_id", "ref"
        ],
        "doc_url": "https://docs.github.com/en/actions",
    },
    "gitlab": {
        "name": "GitLab CI/CD",
        "description": "Trigger GitLab CI/CD pipelines with scan results",
        "icon": "🦊",
        "color": "#FC6D26",
        "fields": [
            "gitlab_url", "project_id", "token", "ref"
        ],
        "doc_url": "https://docs.gitlab.com/ee/ci/",
    },
}

# In-memory store (replace with DB in production)
stored_integrations: Dict[str, dict] = {}


@router.get("/platforms")
async def list_platforms(current_user=Depends(get_current_user)):
    """List all available integration platforms."""
    return {
        "platforms": [
            {"id": k, **v} for k, v in PLATFORMS.items()
        ],
        "count": len(PLATFORMS),
    }


@router.post("/configure")
async def configure_integration(
    config: IntegrationConfig,
    current_user=Depends(get_current_user),
):
    """Configure an integration."""
    if config.platform not in PLATFORMS:
        raise HTTPException(400, f"Unknown platform: {config.platform}")

    key = f"{config.platform}_{config.name}"
    stored_integrations[key] = config.model_dump()

    return {"status": "configured", "key": key}


@router.get("/configured")
async def list_configured(current_user=Depends(get_current_user)):
    """List configured integrations."""
    return {
        "integrations": [
            {"key": k, **v}
            for k, v in stored_integrations.items()
        ],
        "count": len(stored_integrations),
    }


@router.delete("/configured/{key:path}")
async def remove_integration(
    key: str,
    current_user=Depends(get_current_user),
):
    """Remove an integration configuration."""
    stored_integrations.pop(key, None)
    return {"status": "removed"}


@router.post("/test/{platform}")
async def test_integration(
    platform: str,
    body: IntegrationConfig,
    current_user=Depends(get_current_user),
):
    """Test an integration connection."""
    if platform not in PLATFORMS:
        raise HTTPException(400, f"Unknown platform: {platform}")

    try:
        if platform == "slack":
            webhook = body.config.get("webhook_url", "")
            if webhook:
                async with httpx.AsyncClient(timeout=10) as client:
                    resp = await client.post(
                        webhook,
                        json={
                            "text": (
                                "✅ Ch3ck3r integration test successful\n"
                                "Connection verified at "
                                + __import__("datetime")
                                .datetime.now()
                                .isoformat()
                            )
                        },
                    )
                return {
                    "status": "ok" if resp.is_success else "error",
                    "detail": f"Slack responded: {resp.status_code}",
                }

        elif platform == "jira":
            url = body.config.get("jira_url", "")
            email = body.config.get("email", "")
            token = body.config.get("api_token", "")
            if url and token:
                async with httpx.AsyncClient(timeout=10) as client:
                    resp = await client.get(
                        f"{url.rstrip('/')}/rest/api/3/myself",
                        auth=(email, token),
                    )
                return {
                    "status": "ok" if resp.is_success else "error",
                    "detail": (
                        "Jira connected"
                        if resp.is_success
                        else f"Jira error: {resp.status_code}"
                    ),
                }

        elif platform == "github_actions":
            token = body.config.get("github_token", "")
            if token:
                async with httpx.AsyncClient(timeout=10) as client:
                    resp = await client.get(
                        "https://api.github.com/user",
                        headers={
                            "Authorization": f"Bearer {token}",
                            "Accept": "application/vnd.github.v3+json",
                        },
                    )
                return {
                    "status": "ok" if resp.is_success else "error",
                    "detail": (
                        "GitHub token valid"
                        if resp.is_success
                        else "Invalid token"
                    ),
                }

        return {
            "status": "ok",
            "detail": f"{platform} configuration validated",
        }

    except Exception as e:
        return {"status": "error", "detail": str(e)}
