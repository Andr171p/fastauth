from typing import Annotated

from fastapi import Depends, Request

from .schemas import UserHeaders, UserStatus, Role


def get_current_user(request: Request) -> UserHeaders:
    return UserHeaders.from_request(request)


CurrentUser = Annotated[UserHeaders, Depends(get_current_user)]


def required_roles(roles: list[Role]) -> ...:
    ...
