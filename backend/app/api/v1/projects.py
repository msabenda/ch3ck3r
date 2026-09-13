"""Project management endpoints."""
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from typing import List
from uuid import UUID

from app.core.security import get_current_user
from app.db.session import get_db
from app.models import Project, UserRole
from app.schemas import ProjectCreate, ProjectUpdate, ProjectResponse

router = APIRouter()


@router.get("", response_model=List[ProjectResponse])
async def list_projects(
    db: AsyncSession = Depends(get_db),
    current_user=Depends(get_current_user),
):
    """List projects for the current user (admin sees all)."""
    if current_user.role == UserRole.ADMIN.value:
        result = await db.execute(select(Project).order_by(Project.created_at.desc()))
    else:
        result = await db.execute(
            select(Project).where(Project.user_id == UUID(current_user.sub))
            .order_by(Project.created_at.desc())
        )
    projects = result.scalars().all()
    return [
        ProjectResponse(
            id=str(p.id), name=p.name, description=p.description,
            repository_url=p.repository_url, user_id=str(p.user_id),
            created_at=p.created_at, updated_at=p.updated_at,
        )
        for p in projects
    ]


@router.post("", response_model=ProjectResponse, status_code=status.HTTP_201_CREATED)
async def create_project(
    body: ProjectCreate,
    db: AsyncSession = Depends(get_db),
    current_user=Depends(get_current_user),
):
    project = Project(
        name=body.name,
        description=body.description,
        repository_url=body.repository_url,
        user_id=UUID(current_user.sub),
    )
    db.add(project)
    await db.flush()
    await db.refresh(project)
    return ProjectResponse(
        id=str(project.id), name=project.name, description=project.description,
        repository_url=project.repository_url, user_id=str(project.user_id),
        created_at=project.created_at, updated_at=project.updated_at,
    )


@router.get("/{project_id}", response_model=ProjectResponse)
async def get_project(
    project_id: str,
    db: AsyncSession = Depends(get_db),
    current_user=Depends(get_current_user),
):
    result = await db.execute(select(Project).where(Project.id == UUID(project_id)))
    project = result.scalar_one_or_none()
    if not project:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Project not found")
    if current_user.role != UserRole.ADMIN.value and str(project.user_id) != current_user.sub:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Access denied")
    return ProjectResponse(
        id=str(project.id), name=project.name, description=project.description,
        repository_url=project.repository_url, user_id=str(project.user_id),
        created_at=project.created_at, updated_at=project.updated_at,
    )


@router.patch("/{project_id}", response_model=ProjectResponse)
async def update_project(
    project_id: str,
    body: ProjectUpdate,
    db: AsyncSession = Depends(get_db),
    current_user=Depends(get_current_user),
):
    result = await db.execute(select(Project).where(Project.id == UUID(project_id)))
    project = result.scalar_one_or_none()
    if not project:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Project not found")
    if current_user.role != UserRole.ADMIN.value and str(project.user_id) != current_user.sub:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Access denied")

    if body.name is not None:
        project.name = body.name
    if body.description is not None:
        project.description = body.description
    if body.repository_url is not None:
        project.repository_url = body.repository_url

    await db.flush()
    await db.refresh(project)
    return ProjectResponse(
        id=str(project.id), name=project.name, description=project.description,
        repository_url=project.repository_url, user_id=str(project.user_id),
        created_at=project.created_at, updated_at=project.updated_at,
    )


@router.delete("/{project_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_project(
    project_id: str,
    db: AsyncSession = Depends(get_db),
    current_user=Depends(get_current_user),
):
    result = await db.execute(select(Project).where(Project.id == UUID(project_id)))
    project = result.scalar_one_or_none()
    if not project:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Project not found")
    if current_user.role != UserRole.ADMIN.value and str(project.user_id) != current_user.sub:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Access denied")
    await db.delete(project)
    await db.flush()
