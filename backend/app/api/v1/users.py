"""User management endpoints."""
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from typing import List
from uuid import UUID

from app.core.security import get_current_user, hash_password, require_role
from app.db.session import get_db
from app.models import User, UserRole
from app.schemas import UserResponse, UserUpdate

router = APIRouter()


@router.get("", response_model=List[UserResponse])
async def list_users(
    db: AsyncSession = Depends(get_db),
    current_user=Depends(require_role(UserRole.ADMIN.value)),
):
    """List all users (admin only)."""
    result = await db.execute(select(User).order_by(User.created_at.desc()))
    users = result.scalars().all()
    return [
        UserResponse(
            id=str(u.id), email=u.email, full_name=u.full_name,
            role=u.role.value, is_active=u.is_active, created_at=u.created_at,
        )
        for u in users
    ]


@router.get("/{user_id}", response_model=UserResponse)
async def get_user(
    user_id: str,
    db: AsyncSession = Depends(get_db),
    current_user=Depends(require_role(UserRole.ADMIN.value)),
):
    result = await db.execute(select(User).where(User.id == UUID(user_id)))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    return UserResponse(
        id=str(user.id), email=user.email, full_name=user.full_name,
        role=user.role.value, is_active=user.is_active, created_at=user.created_at,
    )


@router.patch("/{user_id}", response_model=UserResponse)
async def update_user(
    user_id: str,
    body: UserUpdate,
    db: AsyncSession = Depends(get_db),
    current_user=Depends(require_role(UserRole.ADMIN.value)),
):
    result = await db.execute(select(User).where(User.id == UUID(user_id)))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    if body.full_name is not None:
        user.full_name = body.full_name
    if body.is_active is not None:
        user.is_active = body.is_active
    if body.role is not None:
        try:
            user.role = UserRole(body.role)
        except ValueError:
            raise HTTPException(status_code=400, detail=f"Invalid role: {body.role}")

    await db.flush()
    await db.refresh(user)
    return UserResponse(
        id=str(user.id), email=user.email, full_name=user.full_name,
        role=user.role.value, is_active=user.is_active, created_at=user.created_at,
    )
