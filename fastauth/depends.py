from typing import Annotated

from fastapi import Depends, Request, HTTPException, status

from .schemas import UserHeaders, UserStatus, UserRole


def get_current_user(request: Request) -> UserHeaders:
    return UserHeaders.from_request(request)


CurrentUser = Annotated[UserHeaders, Depends(get_current_user)]


def require_roles(current_user: CurrentUser, roles: list[UserRole]) -> None:
    if not bool(set(current_user.x_user_roles) & set(roles)):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="Access denied: Not enough permissions"
        )


def require_status(current_user: CurrentUser, statuses: list[UserStatus]) -> None:
    if current_user.x_user_status not in statuses:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="Access denied: Wrong status"
        )
