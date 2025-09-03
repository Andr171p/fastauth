from typing import Annotated

from fastapi import Depends, Request

from .schemas import UserHeaders


def get_current_user(request: Request) -> UserHeaders:
    return UserHeaders.from_request(request)


CurrentUser = Annotated[UserHeaders, Depends(get_current_user)]
