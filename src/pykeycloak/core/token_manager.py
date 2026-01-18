import asyncio
from dataclasses import dataclass, field
from datetime import datetime, timedelta, UTC
from functools import wraps
from typing import Protocol, Callable
import logging
import inspect

from pykeycloak.core.helpers import dataclass_from_dict
from pykeycloak.providers.payloads import ClientCredentialsLoginPayload

logger = logging.getLogger(__name__)


def mark_need_token_verification(func):
    func._need_token_verification = True
    return func


def mark_need_access_token_initialization(func):
    func._need_access_token_initialization = True
    return func


@dataclass(frozen=True)
class RefreshTokenSchema:
    refresh_token_method: Callable
    refresh_token_payload: Callable

@dataclass
class AuthToken:
    access_token: str | None = None
    expires_in: int | None = None
    scope: str | None = None
    token_type: str | None = None
    not_before_policy: int | None = field(metadata={"alias": "not-before-policy"}, default=None)
    session_state: str | None = None
    refresh_token: str | None = None
    id_token: str | None = None
    refresh_expires_in: int | None = None


class AuthTokenValidator:
    @staticmethod
    def is_access_token_valid(token: AuthToken, available_time_frame: int = 30) -> bool:
        if not all([token.access_token, token.expires_in]):
            return False

        now = datetime.now(UTC)

        expires_at = now + timedelta(seconds=token.expires_in)
        buffer = timedelta(seconds=available_time_frame)

        return now < expires_at - buffer
    @staticmethod
    def is_refresh_token_valid(token: AuthToken, available_time_frame: int = 30) -> bool:
        if not all([token.refresh_token, token.refresh_expires_in]):
            return False

        now = datetime.now(UTC)

        expires_at = now + timedelta(seconds=token.refresh_expires_in)
        buffer = timedelta(seconds=available_time_frame)

        return now < expires_at - buffer

class TokenManagerProtocol(Protocol):
    _update_access_token_method: Callable | None = None
    _auth_tokens: AuthToken | None = None

    @property
    def auth_tokens(self) -> AuthToken | None:
        ...

    def is_access_token_valid(self) -> bool:
        ...

    def is_access_token_exists(self) -> bool:
        ...

    def init_update_access_token_api(
            self,
            update_access_token_method: Callable,
    ) -> None: ...

    async def fetch_access_token_using_refresh_token(self) -> AuthToken:
        ...


class TokenManager:
    """
    Double-Checked Locking (Двойная проверка) через asyncio
    Ручное управление локами через threading
    """
    _update_access_token_method: Callable | None = None
    _auth_tokens: AuthToken | None = None

    def __init__(self):
        self._auth_tokens = AuthToken()
        self._lock = asyncio.Lock()
        self.full_inited: bool = False

    @property
    def auth_tokens(self) -> AuthToken | None:
        return self._auth_tokens


    def is_access_token_valid(self) -> bool:
        return AuthTokenValidator.is_access_token_valid(self._auth_tokens)

    def is_access_token_exists(self) -> bool:
        return self._auth_tokens.access_token is not None

    def init_update_access_token_api(
            self,
            update_access_token_method: Callable,
    ) -> None:
        self._update_access_token_method = update_access_token_method

    async def refresh_token(self) -> AuthToken:
        if AuthTokenValidator.is_access_token_valid(self._auth_tokens):
            return self._auth_tokens

        async with self._lock:
            if not self.is_access_token_valid():
                self._auth_tokens = await self.fetch_access_token_using_refresh_token()

        return self._auth_tokens

    async def fetch_access_token_using_refresh_token(self) -> AuthToken:
        response = await self._update_access_token_method(
            refresh_token=self._auth_tokens.refresh_token,
        )

        return AuthToken(**response.json())


class TokenAutoRefresher:
    def __init__(self, token_manager: TokenManagerProtocol):
        self.token_manager: TokenManagerProtocol = token_manager

    def __call__(self, cls):
        orig_init = cls.__init__

        @wraps(orig_init)
        def init_with_setting_refresh_token_api(instance, *args, **kwargs):
            orig_init(instance, *args, **kwargs)
            update_access_token_method = instance.token_manager_update_access_token()
            self.token_manager.init_update_access_token_api(update_access_token_method)

        cls.__init__ = init_with_setting_refresh_token_api

        for name, attr in inspect.getmembers(cls, predicate=inspect.isroutine):
            if callable(attr) and getattr(attr, "_need_token_verification", False):
                setattr(cls, name, self._wrap_method_by_token_verification(attr))

            if callable(attr) and getattr(attr, "_need_access_token_initialization", False):
                setattr(cls, name, self._wrap_method_by_token_initialization(attr))

        cls._token_manager = self.token_manager

        return cls

    def _wrap_method_by_token_initialization(self, func):
        @wraps(func)
        async def wrapper(instance, *args, **kwargs):
            result = await func(instance, *args, **kwargs)

            if isinstance(kwargs.get('payload', None), ClientCredentialsLoginPayload):
                self.token_manager._auth_tokens = dataclass_from_dict(result.json(), AuthToken)

            return result

        return wrapper

    def _wrap_method_by_token_verification(self, func):
        @wraps(func)
        async def wrapper(instance, *args, **kwargs):
            if not self.token_manager.is_access_token_valid():
                await self.token_manager.fetch_access_token_using_refresh_token()
            return await func(instance, access_token=self.token_manager.auth_tokens.access_token, *args, **kwargs)

        return wrapper
