from typing import Self

from enum import StrEnum
from uuid import UUID

from fastapi import Request
from pydantic import (
    BaseModel,
    HttpUrl,
    ConfigDict,
    field_validator,
    field_serializer,
    EmailStr
)


class TokenType(StrEnum):
    ACCESS = "access"
    REFRESH = "refresh"


class Role(StrEnum):
    """Глобальные роли пользователя в рамках области"""
    SUPERADMIN = "superadmin"
    ADMIN = "admin"
    USER = "user"
    GUEST = "guest"


class UserStatus(StrEnum):
    """Статусы пользователя

    Attributes:
        REGISTERED: Зарегистрированный пользователь (ещё не подтверждён email).
        EMAIL_VERIFIED: Пользователь с подтверждённым email.
        ACTIVE: Активны пользователь (после подтверждения email).
        INACTIVE: Неактивный пользователь (не совершал действия долгое время).
        BANNED: Забаненный пользователь.
        DELETED: Удалённый пользователь (при удалении пользователь остаётся в системе).
    """
    REGISTERED = "registered"
    EMAIL_VERIFIED = "email_verified"
    ACTIVE = "active"
    INACTIVE = "inactive"
    BANNED = "banned"
    DELETED = "deleted"


class Claims(BaseModel):
    """Базовая модель для интроспекции JWT"""
    active: bool = False
    cause: str | None = None
    token_type: TokenType | None = None
    iss: HttpUrl | None = None
    sub: str | None = None
    aud: str | None = None
    exp: int | float | None = None
    iat: int | float | None = None
    jti: UUID | None = None

    model_config = ConfigDict(from_attributes=True)

    @field_serializer("iss")
    def serialize_iss(self, iss: HttpUrl) -> str:  # noqa: PLR6301
        return str(iss)


class ClientClaims(Claims):
    realm: str | None = None
    scope: str | None = None


class UserClaims(Claims):
    email: str | None = None
    status: UserStatus | None = None
    realm: str | None = None
    roles: list[Role] | None = None

    @field_validator("roles", mode="before")
    def validate_roles(cls, roles: str | list[Role]) -> list[Role]:
        if isinstance(roles, list):
            return roles
        return [Role(role) for role in roles.split(" ")]


class UserHeaders(BaseModel):
    x_user_id: UUID
    x_user_email: EmailStr
    x_user_status: UserStatus
    x_user_roles: list[Role]

    @classmethod
    def from_request(cls, request: Request) -> Self:
        return cls.model_validate(request.scope["headers"])

    @field_validator("x_user_roles", mode="before")
    def validate_roles(cls, roles: str) -> list[Role]:
        return [Role(role) for role in roles.split(" ")]
