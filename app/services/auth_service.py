from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from app.core.security import (
    create_access_token,
    create_refresh_token,
    hash_password,
    verify_password,
)
from app.db.models import User
from app.schemas.user import LoginRequest, UserCreate


def create_user(
    db: Session,
    user_data: UserCreate,
) -> User:

    existing_user = db.scalar(
        select(User).where(
            or_(
                User.username == user_data.username,
                User.email == user_data.email,
            )
        )
    )

    if existing_user:
        raise ValueError(
            "Username or email already exists"
        )

    user = User(
        username=user_data.username,
        email=user_data.email,
        hashed_password=hash_password(
            user_data.password
        ),
    )

    db.add(user)
    db.commit()
    db.refresh(user)

    return user


def authenticate_user(
    db: Session,
    login_data: LoginRequest,
) -> User | None:

    user = db.scalar(
        select(User).where(
            User.email == login_data.email
        )
    )

    if not user:
        return None

    if not verify_password(
        login_data.password,
        user.hashed_password,
    ):
        return None

    return user


def login_user(
    db: Session,
    login_data: LoginRequest,
) -> dict | None:

    user = authenticate_user(
        db,
        login_data,
    )

    if not user:
        return None

    token_data = {
        "sub": str(user.id),
        "username": user.username,
    }

    access_token = create_access_token(
        token_data
    )

    refresh_token = create_refresh_token(
        token_data
    )

    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer",
    }