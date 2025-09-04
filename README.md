# FastAuth - библиотека для интеграции с SSO сервисом.

## Установка

```shell
pip install "git+https://github.com/Andr171p/fastauth.git"
```

```python
from fastapi import FastAPI, Depends

from fastauth import (
    OAuthMiddleware, 
    RequiredRolesMiddleware, 
    AuthMiddleware, 
    CurrentUser,
    require_roles,
    require_status,
    UserStatus,
    UserRole,
)

app = FastAPI()


@app.get(
    path="/protected",
    dependencies=[
        Depends(require_roles([UserRole.ADMIN])),
        Depends(require_status([UserStatus.EMAIL_VERIFIED]))
    ]
)
async def protected(current_user: CurrentUser):
    return {
        "id": current_user.x_user_id,
        "email": current_user.x_user_email,
        "status": current_user.x_user_status,
        "roles": current_user.x_user_roles,
    }


app.add_middleware(
    OAuthMiddleware,
    base_url="https://sso.example.ru/api/v1",
    realm="some-realm",
)

app.add_middleware(
    AuthMiddleware,
    base_url="https://sso.example.ru/api/v1",
    realm="some-realm",
    public_endpoints=["/home", "/courses"],
)

REQUIRED_ROLES_ENDPOINTS: dict[str, dict[str, list[str]]] = {
    "/admin": {"*": ["admin"]},
    "/courses": {
        "get": ["user", "guest", "admin", "moderator"],
        "post": ["admin", "moderator"],
        "put": ["admin", "moderator"],
        "delete": ["admin", "moderator"],
    },
}

app.add_middleware(
    RequiredRolesMiddleware,
    required_roles_endpoints=REQUIRED_ROLES_ENDPOINTS,
)

```