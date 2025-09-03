import logging

import aiohttp
from fastapi import HTTPException, status
from starlette.datastructures import MutableHeaders
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import Response
from starlette.types import ASGIApp

from .constants import DOCS_ENDPOINTS
from .schemas import ClientClaims, TokenType, UserClaims

logger = logging.getLogger("fastauth")


class OAuthMiddleware(BaseHTTPMiddleware):
    """Middleware для аутентификации клиентских приложений через OAuth 2.0.

    Проверяет валидность access token'а клиента через эндпоинт интроспекции
    и добавляет информацию о клиенте в заголовки запроса.
    """
    def __init__(self, app: ASGIApp, base_url: str, realm: str) -> None:
        """
        :param base_url: Базовый URL SSO сервера.
        :param realm: Область в которой работает сервис.
        """
        super().__init__(app)
        self.base_url = base_url
        self.realm = realm

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        if request.url.path in DOCS_ENDPOINTS:
            return await call_next(request)
        header = request.headers.get("Client authorization")
        if not header or not header.startswith("Bearer "):
            logger.debug("Invalid authorization header: %s", header)
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid bearer token"
            )
        token = header.replace("Bearer ", "")
        claims = await self._introspect_token(token)
        if not claims.active:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED, detail=claims.cause
            )
        request_with_claims = self._inject_claims(request, claims)
        logger.debug("Client %s authentication successfully!", claims.sub)
        return await call_next(request_with_claims)

    async def _introspect_token(self, token: str) -> ClientClaims:
        async with aiohttp.ClientSession(base_url=self.base_url) as session, session.post(
                url=f"{self.realm}/oauth/introspect",
                headers={"Content-Type": "application/json"},
                json={"token": token},
        ) as response:
            data = await response.json()
            if response.status == status.HTTP_400_BAD_REQUEST:
                detail = data.get("detail", "Unknown error")
                logger.debug("Request failed: %s", detail)
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST, detail=detail
                )
            if response.status == status.HTTP_401_UNAUTHORIZED:
                detail = data.get("detail", "Unknown error")
                logger.debug("Unauthorized request: %s", detail)
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED, detail=detail
                )
            return ClientClaims.model_validate(data)

    @staticmethod
    def _inject_claims(request: Request, claims: ClientClaims) -> Request:
        """Дополняет запрос новыми заголовками с информацией о клиенте."""
        headers = MutableHeaders(scope=request.scope)
        headers["X-Client-Id"] = claims.sub
        headers["X-Client-Scope"] = claims.scope
        headers["X-Client-Realm"] = claims.realm
        request.scope = headers.raw
        return request


class AuthMiddleware(BaseHTTPMiddleware):
    """ Middleware для аутентификации пользователей через сессионные куки и токены.

    Проверяет валидность сессии пользователя и access token'а, добавляет
    информацию о пользователе в заголовки запроса.
    """
    def __init__(
            self,
            app: ASGIApp,
            base_url: str,
            realm: str,
            public_endpoints: list[str] | None = None,
    ) -> None:
        """
        :param base_url: Базовый URL SSO сервера.
        :param realm: Область в которой сервис аутентифицирует пользователя.
        :param public_endpoints: Ендпоинты не требующие авторизации.
        """
        super().__init__(app)
        self.base_url = base_url
        self.realm = realm
        self.public_endpoints = public_endpoints

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        if request.url.path in DOCS_ENDPOINTS or request.url.path in self.public_endpoints:
            logger.debug(
                "Skipping authentication for public endpoint: %s", request.url.path
            )
            return await call_next(request)
        session_id = request.cookies.get("session_id")
        if session_id is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED, detail="Session is missing"
            )
        header = request.headers.get("Authorization")
        if not header or not header.startswith("Bearer "):
            logger.debug("Invalid authorization header: %s", header)
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authorization header"
            )
        token = header.replace("Bearer ", "")
        claims = await self._introspect_token(token, cookies=request.cookies)
        if claims.token_type != TokenType.ACCESS:
            print(claims)
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid token type"
            )
        request_with_claims = self._inject_claims(request, claims)
        logger.debug("User %s authenticated successfully!", claims.sub)
        return await call_next(request_with_claims)

    async def _introspect_token(self, token: str, cookies: dict[str, str]) -> UserClaims:
        async with aiohttp.ClientSession(base_url=self.base_url) as session, session.post(
                url=f"{self.realm}/auth/introspect",
                headers={"Content-Type": "application/json"},
                json={"token": token},
                cookies=cookies
        ) as response:
            data = await response.json()
            if response.status == status.HTTP_401_UNAUTHORIZED:
                detail = data.get("detail", "Unknown error")
                logger.debug("Unauthorized request: %s", detail)
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED, detail=detail
                )
            return UserClaims.model_validate(data)

    @staticmethod
    def _inject_claims(request: Request, claims: UserClaims) -> Request:
        """Дополняет запрос новыми заголовками с информацией о пользователе."""
        headers = MutableHeaders(scope=request.scope)
        headers["X-User-Id"] = claims.sub
        headers["X-User-Roles"] = " ".join(claims.roles)
        headers["X-User-Realm"] = claims.realm
        headers["X-User-Status"] = claims.status
        headers["X-User-Email"] = claims.email
        request.scope["headers"] = headers.raw
        return request


class RequiredRolesMiddleware(BaseHTTPMiddleware):
    """Middleware для авторизации на основе глобальных ролей пользователя.

    Проверяет наличие необходимых ролей у пользователя для доступа к эндпоинтам.
    """
    def __init__(
            self, app: ASGIApp, required_roles_endpoints: dict[str, dict[str, list[str]]]
    ) -> None:
        """
        :param required_roles_endpoints: Маппинг ролей к методам ендпоинтов.
        """
        super().__init__(app)
        self.required_roles_endpoints = required_roles_endpoints

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        if request.url.path in self.required_roles_endpoints:
            methods_roles = self.required_roles_endpoints[request.url.path]
            required_roles = methods_roles.get(request.method.lower(), methods_roles.get("*", []))
            if required_roles:
                requested_roles = request.scope["headers"].get("X-User-Roles").split(" ")
                if not any(required_role in requested_roles for required_role in required_roles):
                    logger.debug(
                        "Access denied for user %s, with cause: insufficient roles",
                        request.scope["headers"].get("X-User-Id", "Unknown"),
                    )
                    raise HTTPException(
                        status_code=status.HTTP_403_FORBIDDEN,
                        detail=f"Not authorized: required roles {required_roles}"
                    )
        return await call_next(request)
