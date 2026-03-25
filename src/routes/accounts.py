from datetime import datetime, timezone
from typing import cast

from fastapi import APIRouter, Depends, status, HTTPException
from sqlalchemy import select, delete
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import Session, joinedload

from config import get_jwt_auth_manager, get_settings, BaseAppSettings
from database import (
    get_db,
    UserModel,
    UserGroupModel,
    UserGroupEnum,
    ActivationTokenModel,
    PasswordResetTokenModel,
    RefreshTokenModel
)
from exceptions import BaseSecurityError
from schemas.accounts import (
    UserRegistrationRequestSchema,
    UserRegistrationResponseSchema,
    UserActivationRequestSchema,
    PasswordResetRequestSchema,
    PasswordResetCompleteRequestSchema,
    UserLoginRequestSchema,
    UserLoginResponseSchema,
    TokenRefreshRequestSchema,
    TokenRefreshResponseSchema,
    MessageResponseSchema,
)
from security.interfaces import JWTAuthManagerInterface

router = APIRouter()


@router.post("/register/", response_model=UserRegistrationResponseSchema, status_code=201)
async def register_user(
    user_data: UserRegistrationRequestSchema,
    db: AsyncSession = Depends(get_db),
):
    existing = (await db.execute(
        select(UserModel).where(UserModel.email == user_data.email)
    )).scalars().first()

    if existing:
        raise HTTPException(
            status_code=409,
            detail=f"A user with this email {user_data.email} already exists.",
        )

    user_group = (await db.execute(
        select(UserGroupModel).where(UserGroupModel.name == UserGroupEnum.USER)
    )).scalars().first()

    user = UserModel.create(
        email=user_data.email,
        raw_password=user_data.password,
        group_id=cast(int, user_group.id),
    )
    db.add(user)

    try:
        await db.flush()
        activation_token = ActivationTokenModel(user_id=cast(int, user.id))
        db.add(activation_token)
        await db.commit()
    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=500,
            detail="An error occurred during user creation.",
        )

    return UserRegistrationResponseSchema(id=cast(int, user.id), email=user.email)


@router.post("/activate/", response_model=MessageResponseSchema, status_code=200)
async def activate_account(
    payload: UserActivationRequestSchema,
    db: AsyncSession = Depends(get_db),
):
    user = (await db.execute(
        select(UserModel).where(UserModel.email == payload.email)
    )).scalars().first()

    if not user:
        raise HTTPException(status_code=400, detail="Invalid or expired activation token.")

    if user.is_active:
        raise HTTPException(status_code=400, detail="User account is already active.")

    token_record = (await db.execute(
        select(ActivationTokenModel).where(
            ActivationTokenModel.user_id == user.id,
            ActivationTokenModel.token == payload.token,
        )
    )).scalars().first()

    if not token_record:
        raise HTTPException(status_code=400, detail="Invalid or expired activation token.")

    expires_at = cast(datetime, token_record.expires_at).replace(tzinfo=timezone.utc)
    if expires_at < datetime.now(timezone.utc):
        raise HTTPException(status_code=400, detail="Invalid or expired activation token.")

    user.is_active = True
    await db.delete(token_record)
    await db.commit()

    return MessageResponseSchema(message="User account activated successfully.")


@router.post("/password-reset/request/", response_model=MessageResponseSchema, status_code=200)
async def request_password_reset(
    payload: PasswordResetRequestSchema,
    db: AsyncSession = Depends(get_db),
):
    success_message = MessageResponseSchema(
        message="If you are registered, you will receive an email with instructions."
    )

    user = (await db.execute(
        select(UserModel).where(UserModel.email == payload.email)
    )).scalars().first()

    if not user or not user.is_active:
        return success_message

    await db.execute(
        delete(PasswordResetTokenModel).where(PasswordResetTokenModel.user_id == user.id)
    )

    reset_token = PasswordResetTokenModel(user_id=cast(int, user.id))
    db.add(reset_token)
    await db.commit()

    return success_message


@router.post("/reset-password/complete/", response_model=MessageResponseSchema, status_code=200)
async def reset_password_complete(
    payload: PasswordResetCompleteRequestSchema,
    db: AsyncSession = Depends(get_db),
):

    user = (await db.execute(
        select(UserModel).where(UserModel.email == payload.email)
    )).scalars().first()

    if not user or not user.is_active:
        raise HTTPException(status_code=400, detail="Invalid email or token.")

    token_record = (await db.execute(
        select(PasswordResetTokenModel).where(PasswordResetTokenModel.user_id == user.id)
    )).scalars().first()

    if not token_record:
        raise HTTPException(status_code=400, detail="Invalid email or token.")

    expires_at = cast(datetime, token_record.expires_at).replace(tzinfo=timezone.utc)
    if token_record.token != payload.token or expires_at < datetime.now(timezone.utc):
        await db.delete(token_record)
        await db.commit()
        raise HTTPException(status_code=400, detail="Invalid email or token.")

    try:
        user.password = payload.password
        await db.delete(token_record)
        await db.commit()
    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=500,
            detail="An error occurred while resetting the password.",
        )

    return MessageResponseSchema(message="Password reset successfully.")


@router.post("/login/", response_model=UserLoginResponseSchema, status_code=201)
async def login_user(
    payload: UserLoginRequestSchema,
    db: AsyncSession = Depends(get_db),
    jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
    settings: BaseAppSettings = Depends(get_settings),
):
    user = (await db.execute(
        select(UserModel).where(UserModel.email == payload.email)
    )).scalars().first()

    if not user or not user.verify_password(payload.password):
        raise HTTPException(status_code=401, detail="Invalid email or password.")

    if not user.is_active:
        raise HTTPException(status_code=403, detail="User account is not activated.")

    user_id = cast(int, user.id)
    access_token = jwt_manager.create_access_token({"user_id": user_id})
    refresh_token = jwt_manager.create_refresh_token({"user_id": user_id})

    refresh_token_record = RefreshTokenModel.create(
        user_id=user_id,
        days_valid=settings.LOGIN_TIME_DAYS,
        token=refresh_token,
    )
    db.add(refresh_token_record)

    try:
        await db.commit()
    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=500,
            detail="An error occurred while processing the request.",
        )

    return UserLoginResponseSchema(access_token=access_token, refresh_token=refresh_token)


@router.post("/refresh/", response_model=TokenRefreshResponseSchema, status_code=200)
async def refresh_access_token(
    payload: TokenRefreshRequestSchema,
    db: AsyncSession = Depends(get_db),
    jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
):

    try:
        token_data = jwt_manager.decode_refresh_token(payload.refresh_token)
    except BaseSecurityError as e:
        raise HTTPException(status_code=400, detail=str(e))

    user_id = token_data.get("user_id")

    token_record = (await db.execute(
        select(RefreshTokenModel).where(RefreshTokenModel.token == payload.refresh_token)
    )).scalars().first()

    if not token_record:
        raise HTTPException(status_code=401, detail="Refresh token not found.")

    user = (await db.execute(
        select(UserModel).where(UserModel.id == user_id)
    )).scalars().first()

    if not user:
        raise HTTPException(status_code=404, detail="User not found.")

    access_token = jwt_manager.create_access_token({"user_id": cast(int, user.id)})

    return TokenRefreshResponseSchema(access_token=access_token)
