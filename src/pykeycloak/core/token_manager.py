import asyncio
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta, UTC
from functools import wraps
from typing import Protocol, Callable


def mark_need_token_verification(func):
    func._need_token_verification = True
    return func


@dataclass(frozen=True)
class RefreshTokenSchema:
    refresh_token_method: Callable
    refresh_token_payload: Callable


@dataclass
class AuthTokens:
    access_token: str | None = None
    expires_at: str | datetime = None
    refresh_token: str | None = None

    def is_access_token_valid(self, available_time_frame: int = 30) -> bool:
        return self.access_token and datetime.now(UTC) < self.expires_at - timedelta(seconds=available_time_frame)

    def is_refresh_token_valid(self, available_time_frame: int = 30) -> bool:
        return self.refresh_token and datetime.now(UTC) < self.expires_at - timedelta(seconds=available_time_frame)


class TokenManagerProtocol(Protocol):
    _refresh_token_method: Callable | None = None
    _refresh_token_payload: Callable | None = None
    _auth_tokens: AuthTokens | None = None

    @property
    def auth_tokens(self) -> AuthTokens | None:
        ...

    def is_token_valid(self) -> bool:
        ...

    def init_refresh_token_api(
            self,
            refresh_token_method: Callable,
            refresh_token_payload: Callable
    ) -> None: ...

    async def refresh_token(self) -> AuthTokens:
        ...


class TokenManager:
    """
    Double-Checked Locking (Двойная проверка) через asyncio
    Ручное управление локами через threading
    """
    _refresh_token_method: Callable | None = None
    _refresh_token_payload: Callable | None = None

    def __init__(self):
        self._auth_tokens: AuthTokens = AuthTokens()
        self._lock = asyncio.Lock()
        self.full_inited: bool = False

    @property
    def auth_tokens(self):
        return self._auth_tokens

    def is_token_valid(self) -> bool:
        return self._auth_tokens.is_access_token_valid()

    def init_refresh_token_api(
            self,
            refresh_token_method: Callable,
            refresh_token_payload: Callable
    ) -> None:
        self._refresh_token_method = refresh_token_method
        self._refresh_token_payload = refresh_token_payload

    async def refresh_token(self) -> AuthTokens:
        if self._auth_tokens.is_access_token_valid():
            return self._auth_tokens

        async with self._lock:
            if self._auth_tokens.is_access_token_valid():
                return self._auth_tokens

            self._auth_tokens = await self.fetch_new_token()

        return self._auth_tokens

    async def fetch_new_token(self) -> AuthTokens:
        return await self._refresh_token_method(self._refresh_token_payload(
            refresh_token=self._auth_tokens.refresh_token,
        ))


class TokenAutoRefresher:
    def __init__(self, token_manager: TokenManagerProtocol):
        self.token_manager: TokenManagerProtocol = token_manager

    def __call__(self, cls):
        if not hasattr(cls, "refresh_token_schema"):
            raise TypeError(
                f"Class '{cls.__name__}' must implement 'refresh_token_schema' method "
                f"to be used with @ExpiredTokenProtector"
            )

        for name, attr in list(cls.__dict__.items()):
            if callable(attr) and getattr(attr, "_need_token_verification", False):
                setattr(cls, name, self._wrap_method_by_token_verification(attr))

        self.token_manager.init_refresh_token_api(**asdict(cls.refresh_token_schema()))

        return cls

    def _wrap_method_by_token_verification(self, func):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            if not self.token_manager.auth_tokens.is_access_token_valid():
                await self.token_manager.refresh_token()
            return await func(self, *args, **kwargs)

        return wrapper
