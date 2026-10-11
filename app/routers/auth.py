from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, status
from jose import JWTError
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.security import (
    create_access_token,
    decode_token,
)
from app.db.database import get_db
from app.db.models import RefreshToken
from app.schemas.user import (
    LoginRequest,
    RefreshTokenRequest,
    TokenResponse,
    UserCreate,
    UserResponse,
)
from app.services.auth_service import (
    create_user,
    login_user,
)


router = APIRouter(
    prefix="/auth",
    tags=["Authentication"],
)


@router.post(
    "/register",
    response_model=UserResponse,
    status_code=status.HTTP_201_CREATED,
)
def register(
    user_data: UserCreate,
    db: Session = Depends(get_db),
):
    try:
        return create_user(
            db,
            user_data,
        )

    except ValueError as error:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=str(error),
        )


@router.post(
    "/login",
    response_model=TokenResponse,
)
def login(
    login_data: LoginRequest,
    db: Session = Depends(get_db),
):
    tokens = login_user(
        db,
        login_data,
    )

    if not tokens:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password",
        )

    payload = decode_token(
        tokens["refresh_token"]
    )

    refresh_token_record = RefreshToken(
        user_id=int(payload["sub"]),
        token=tokens["refresh_token"],
        expires_at=datetime.now(timezone.utc)
        + timedelta(
            days=settings.refresh_token_expire_days
        ),
    )

    db.add(refresh_token_record)
    db.commit()

    return tokens


@router.post(
    "/refresh",
    response_model=TokenResponse,
)
def refresh_token(
    request: RefreshTokenRequest,
    db: Session = Depends(get_db),
):
    stored_token = db.scalar(
        select(RefreshToken).where(
            RefreshToken.token
            == request.refresh_token,
            RefreshToken.revoked.is_(False),
        )
    )

    if not stored_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token revoked or invalid",
        )

    try:
        payload = decode_token(
            request.refresh_token
        )

        if payload.get("type") != "refresh":
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid refresh token",
            )

        user_id = payload.get("sub")
        username = payload.get("username")

        access_token = create_access_token(
            {
                "sub": user_id,
                "username": username,
            }
        )

        return {
            "access_token": access_token,
            "refresh_token": request.refresh_token,
            "token_type": "bearer",
        }

    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired refresh token",
        )


@router.post("/logout")
def logout(
    request: RefreshTokenRequest,
    db: Session = Depends(get_db),
):
    stored_token = db.scalar(
        select(RefreshToken).where(
            RefreshToken.token
            == request.refresh_token
        )
    )

    if not stored_token:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Refresh token not found",
        )

    stored_token.revoked = True

    db.commit()

    return {
        "message": "Successfully logged out"
    }