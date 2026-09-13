"""GitHub integration endpoints."""
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from app.db.session import get_db
from app.core.security import get_current_user
from pydantic import BaseModel
import httpx

router = APIRouter()


class GitHubConnectRequest(BaseModel):
    repository_url: str
    token: str
    branch: str = "main"


@router.post("/github/connect")
async def connect_github_repo(
    body: GitHubConnectRequest,
    db: AsyncSession = Depends(get_db),
    current_user=Depends(get_current_user),
):
    """Verify GitHub token has access to the repo and return metadata."""
    # Parse owner/repo from URL
    parts = body.repository_url.rstrip("/").rstrip(".git").split("/")
    if len(parts) < 2:
        raise HTTPException(status_code=400, detail="Invalid repository URL")
    owner, repo = parts[-2], parts[-1]

    # Test token against GitHub API
    async with httpx.AsyncClient(timeout=15) as client:
        resp = await client.get(
            f"https://api.github.com/repos/{owner}/{repo}",
            headers={
                "Authorization": f"Bearer {body.token}",
                "Accept": "application/vnd.github.v3+json",
            },
        )
    if resp.status_code != 200:
        detail = "unknown error"
        try:
            detail = resp.json().get("message", "unknown error")
        except Exception:
            pass
        raise HTTPException(
            status_code=400,
            detail=f"GitHub access check failed: {detail}",
        )

    data = resp.json()
    return {
        "status": "ok",
        "owner": owner,
        "repo": repo,
        "full_name": data.get("full_name"),
        "private": data.get("private", False),
        "default_branch": data.get("default_branch", "main"),
        "description": data.get("description"),
        "language": data.get("language"),
        "stars": data.get("stargazers_count", 0),
        "url": data.get("html_url"),
    }
