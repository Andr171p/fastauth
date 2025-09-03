from fastapi import FastAPI

from fastauth.middlewares import OAuthMiddleware, RequiredRolesMiddleware, AuthMiddleware

app = FastAPI()

app.add_middleware(OAuthMiddleware(
    base_url="https://sso.example.ru/api/v1",
    realm="some-realm",
))

app.add_middleware(AuthMiddleware(
    base_url="https://sso.example.ru/api/v1",
    realm="some-realm",
    public_endpoints=["/home", "/courses"]
    )
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

app.add_middleware(RequiredRolesMiddleware(
    required_roles_endpoints=REQUIRED_ROLES_ENDPOINTS
))
