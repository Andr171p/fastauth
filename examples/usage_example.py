from fastapi import FastAPI

from fastauth import OAuthMiddleware, RequiredRolesMiddleware, AuthMiddleware, CurrentUser

app = FastAPI()


@app.get("/protected")
async def protected(current_user: CurrentUser):
    return {
        "id": current_user.id,
        "email": current_user.email,
        "status": current_user.status,
        "roles": current_user.roles,
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
    public_endpoints=["/home", "/"],
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
