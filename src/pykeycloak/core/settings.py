import os
import ssl
from collections.abc import Callable, Iterable
from collections.abc import Mapping as ABCMapping
from copy import deepcopy
from dataclasses import dataclass, field
from typing import Any

from httpx import AsyncHTTPTransport, BaseTransport, HTTPTransport, Limits, Timeout
from httpx._config import DEFAULT_MAX_REDIRECTS
from httpx._transports.default import SOCKET_OPTION
from httpx._types import (
    AuthTypes,
    CertTypes,
    CookieTypes,
    HeaderTypes,
    ProxyTypes,
    QueryParamTypes,
    TimeoutTypes,
    URLTypes,
)

from .constants import KEYCLOAK_HTTPX_CLIENT_PARAMS_TIMEOUT_DEFAULT, \
    KEYCLOAK_HTTPX_CLIENT_PARAMS_MAX_CONNECTIONS_DEFAULT, \
    KEYCLOAK_HTTPX_CLIENT_PARAMS_MAX_KEEPALIVE_CONNECTIONS_DEFAULT, \
    KEYCLOAK_HTTPX_CLIENT_PARAMS_DEFAULT_ENCODING_DEFAULT, KEYCLOAK_HTTPX_CLIENT_PARAMS_TRUST_ENV_DEFAULT, \
    KEYCLOAK_HTTPX_CLIENT_PARAMS_HTTP2_DEFAULT, KEYCLOAK_HTTPX_CLIENT_PARAMS_HTTP1_DEFAULT, \
    KEYCLOAK_HTTPX_CLIENT_PARAMS_SSL_VERIFY_DEFAULT, KEYCLOAK_HTTPX_CLIENT_PARAMS_FOLLOW_REDIRECTS_DEFAULT, \
    KEYCLOAK_HTTPX_HTTP_TRANSPORT_HTTP_MAX_KEEPALIVE_CONNECTIONS_DEFAULT, \
    KEYCLOAK_HTTPX_HTTP_TRANSPORT_HTTP_RETRIES_DEFAULT, KEYCLOAK_HTTPX_HTTP_TRANSPORT_HTTP_HTTP2_DEFAULT, \
    KEYCLOAK_HTTPX_HTTP_TRANSPORT_HTTP_HTTP1_DEFAULT, KEYCLOAK_HTTPX_HTTP_TRANSPORT_HTTP_TRUST_ENV_DEFAULT, \
    KEYCLOAK_HTTPX_HTTP_TRANSPORT_HTTP_VERIFY_DEFAULT, \
    KEYCLOAK_HTTPX_HTTP_TRANSPORT_HTTP_MAX_CONNECTIONS_DEFAULT
from .headers import Headers
from .helpers import getenv_bool, getenv_int, getenv_optional, getenv_required_url


@dataclass
class HttpTransportSettings:
    verify: ssl.SSLContext | str | bool = True
    cert: CertTypes | None = None
    trust_env: bool = True
    http1: bool = True
    http2: bool = False
    limits: Limits = field(
        default_factory=lambda: Limits(max_connections=KEYCLOAK_HTTPX_HTTP_TRANSPORT_HTTP_MAX_CONNECTIONS_DEFAULT, max_keepalive_connections=KEYCLOAK_HTTPX_HTTP_TRANSPORT_HTTP_MAX_KEEPALIVE_CONNECTIONS_DEFAULT)
    )
    proxy: ProxyTypes | None = None
    uds: str | None = None
    local_address: str | None = None
    retries: int = KEYCLOAK_HTTPX_HTTP_TRANSPORT_HTTP_RETRIES_DEFAULT
    socket_options: list["SOCKET_OPTION"] | None = field(
        init=False, repr=False, default=None
    )

    def __post_init__(self) -> None:
        if not (self.http1 or self.http2):
            raise ValueError(
                "At least one of http1=True or http2=True must be enabled."
            )
        if self.retries < 0:
            raise ValueError("retries must be >= 0")

    def to_dict(self) -> dict[str, Any]:
        return {
            "verify": self.verify,
            "cert": self.cert,
            "http1": self.http1,
            "http2": self.http2,
            "limits": self.limits,
            "trust_env": self.trust_env,
            "proxy": self.proxy,
            "uds": self.uds,
            "local_address": self.local_address,
            "retries": self.retries,
            "socket_options": deepcopy(self.socket_options),
        }

    @classmethod
    def from_env(cls) -> "HttpTransportSettings":
        return cls(
            verify=getenv_bool("KEYCLOAK_HTTPX_HTTP_TRANSPORT_HTTP_VERIFY", KEYCLOAK_HTTPX_HTTP_TRANSPORT_HTTP_VERIFY_DEFAULT),
            cert=getenv_optional("KEYCLOAK_HTTPX_HTTP_TRANSPORT_HTTP_CERT"),
            trust_env=getenv_bool("KEYCLOAK_HTTPX_HTTP_TRANSPORT_HTTP_TRUST_ENV", KEYCLOAK_HTTPX_HTTP_TRANSPORT_HTTP_TRUST_ENV_DEFAULT),
            http1=getenv_bool("KEYCLOAK_HTTPX_HTTP_TRANSPORT_HTTP_HTTP1", KEYCLOAK_HTTPX_HTTP_TRANSPORT_HTTP_HTTP1_DEFAULT),
            http2=getenv_bool("KEYCLOAK_HTTPX_HTTP_TRANSPORT_HTTP_HTTP2", KEYCLOAK_HTTPX_HTTP_TRANSPORT_HTTP_HTTP2_DEFAULT),
            retries=getenv_int("KEYCLOAK_HTTPX_HTTP_TRANSPORT_HTTP_RETRIES", KEYCLOAK_HTTPX_HTTP_TRANSPORT_HTTP_RETRIES_DEFAULT),
            proxy=getenv_optional("KEYCLOAK_HTTPX_HTTP_TRANSPORT_HTTP_PROXY"),
            uds=getenv_optional("KEYCLOAK_HTTPX_HTTP_TRANSPORT_HTTP_UDS"),
            local_address=getenv_optional(
                "KEYCLOAK_HTTPX_HTTP_TRANSPORT_HTTP_LOCAL_ADDRESSES"
            ),
            limits=Limits(
                max_connections=getenv_int(
                    "KEYCLOAK_HTTPX_HTTP_TRANSPORT_HTTP_MAX_CONNECTIONS", KEYCLOAK_HTTPX_HTTP_TRANSPORT_HTTP_MAX_CONNECTIONS_DEFAULT
                ),
                max_keepalive_connections=getenv_int(
                    "KEYCLOAK_HTTPX_HTTP_TRANSPORT_HTTP_MAX_KEEPALIVE_CONNECTIONS", KEYCLOAK_HTTPX_HTTP_TRANSPORT_HTTP_MAX_KEEPALIVE_CONNECTIONS_DEFAULT
                ),
            ),
        )


@dataclass
class ClientSettings:
    auth: AuthTypes | None = None
    params: QueryParamTypes | None = None
    headers: HeaderTypes | Headers | None = None
    cookies: CookieTypes | None = None
    verify: ssl.SSLContext | str | bool = KEYCLOAK_HTTPX_CLIENT_PARAMS_SSL_VERIFY_DEFAULT
    cert: CertTypes | None = None
    http1: bool = KEYCLOAK_HTTPX_CLIENT_PARAMS_HTTP1_DEFAULT
    http2: bool = KEYCLOAK_HTTPX_CLIENT_PARAMS_HTTP2_DEFAULT
    proxy: ProxyTypes | None = None
    mounts: dict[str, BaseTransport | None] | None = None
    timeout: TimeoutTypes = field(default_factory=lambda: Timeout(timeout=KEYCLOAK_HTTPX_CLIENT_PARAMS_TIMEOUT_DEFAULT))
    follow_redirects: bool = False
    limits: Limits = field(
        default_factory=lambda: Limits(
            max_connections=KEYCLOAK_HTTPX_CLIENT_PARAMS_MAX_CONNECTIONS_DEFAULT,
            max_keepalive_connections=KEYCLOAK_HTTPX_CLIENT_PARAMS_MAX_KEEPALIVE_CONNECTIONS_DEFAULT
        )
    )
    max_redirects: int = DEFAULT_MAX_REDIRECTS
    event_hooks: dict[str, list[Callable[..., Any]]] | None = None
    base_url: URLTypes = ""
    transport: AsyncHTTPTransport | HTTPTransport | None = None
    trust_env: bool = KEYCLOAK_HTTPX_CLIENT_PARAMS_TRUST_ENV_DEFAULT
    default_encoding: str | Callable[[bytes], str] = KEYCLOAK_HTTPX_CLIENT_PARAMS_DEFAULT_ENCODING_DEFAULT

    def __post_init__(self) -> None:
        for attr in ["params", "headers", "cookies", "mounts"]:
            val = getattr(self, attr)
            if isinstance(val, ABCMapping):
                setattr(self, attr, deepcopy(val))

        if isinstance(self.event_hooks, ABCMapping):
            self.event_hooks = {
                key: list(value) for key, value in self.event_hooks.items()
            }
        elif self.event_hooks is None:
            self.event_hooks = {}

        if not (self.http1 or self.http2):
            raise ValueError(
                "At least one of http1=True or http2=True must be enabled."
            )

        if self.max_redirects < 0:
            raise ValueError("max_redirects must be >= 0")

    @classmethod
    def from_env(cls) -> "ClientSettings":
        """Create ClientSettings using .env variables."""
        return cls(
            base_url=getenv_required_url("KEYCLOAK_BASE_URL"),
            verify=getenv_bool("KEYCLOAK_HTTPX_HTTP_VERIFY", KEYCLOAK_HTTPX_CLIENT_PARAMS_SSL_VERIFY_DEFAULT),
            http1=getenv_bool("KEYCLOAK_HTTPX_CLIENT_PARAMS_HTTP1", KEYCLOAK_HTTPX_CLIENT_PARAMS_HTTP1_DEFAULT),
            http2=getenv_bool("KEYCLOAK_HTTPX_CLIENT_PARAMS_HTTP2", KEYCLOAK_HTTPX_CLIENT_PARAMS_HTTP2_DEFAULT),
            follow_redirects=getenv_bool(
                "KEYCLOAK_HTTPX_CLIENT_PARAMS_FOLLOW_REDIRECTS", KEYCLOAK_HTTPX_CLIENT_PARAMS_FOLLOW_REDIRECTS_DEFAULT
            ),
            trust_env=getenv_bool("KEYCLOAK_HTTPX_CLIENT_PARAMS_TRUST_ENV", KEYCLOAK_HTTPX_CLIENT_PARAMS_TRUST_ENV_DEFAULT),
            timeout=Timeout(
                timeout=float(os.getenv("KEYCLOAK_HTTPX_CLIENT_PARAMS_TIMEOUT", KEYCLOAK_HTTPX_CLIENT_PARAMS_TIMEOUT_DEFAULT))
            ),
            limits=Limits(
                max_connections=getenv_int(
                    "KEYCLOAK_HTTPX_CLIENT_PARAMS_MAX_CONNECTIONS", KEYCLOAK_HTTPX_CLIENT_PARAMS_MAX_CONNECTIONS_DEFAULT
                ),
                max_keepalive_connections=getenv_int(
                    "KEYCLOAK_HTTPX_CLIENT_PARAMS_MAX_KEEPALIVE_CONNECTIONS", KEYCLOAK_HTTPX_CLIENT_PARAMS_MAX_KEEPALIVE_CONNECTIONS_DEFAULT
                ),
            ),
            max_redirects=getenv_int(
                "KEYCLOAK_HTTPX_CLIENT_PARAMS_MAX_REDIRECTS", DEFAULT_MAX_REDIRECTS
            ),
            default_encoding=os.getenv(
                "KEYCLOAK_HTTPX_CLIENT_PARAMS_DEFAULT_ENCODING", KEYCLOAK_HTTPX_CLIENT_PARAMS_DEFAULT_ENCODING_DEFAULT
            ),
        )

    def to_dict(self) -> dict[str, Any]:
        """Convert settings to a serializable dictionary."""
        return {
            "auth": self.auth,
            "params": deepcopy(self.params),
            "headers": deepcopy(self.headers),
            "cookies": deepcopy(self.cookies),
            "verify": self.verify,
            "cert": self.cert,
            "http1": self.http1,
            "http2": self.http2,
            "proxy": self.proxy,
            "mounts": deepcopy(self.mounts),
            "timeout": self.timeout,
            "follow_redirects": self.follow_redirects,
            "limits": self.limits,
            "max_redirects": self.max_redirects,
            "event_hooks": deepcopy(self.event_hooks),
            "base_url": self.base_url,
            "transport": self.transport,
            "trust_env": self.trust_env,
            "default_encoding": self.default_encoding,
        }

    def add_event_hook(self, event: str, func: Callable[..., Any]) -> None:
        if isinstance(self.event_hooks, dict):
            self.event_hooks.setdefault(event, []).append(func)

    def extend_event_hooks(
        self, event: str, funcs: Iterable[Callable[..., Any]]
    ) -> None:
        if isinstance(self.event_hooks, dict):
            self.event_hooks.setdefault(event, []).extend(funcs)

    def __repr__(self) -> str:
        return (
            f"ClientSettings("
            f"auth={self.auth!r}, params={self.params!r}, headers={self.headers!r}, "
            f"cookies={self.cookies!r}, verify={self.verify!r}, cert={self.cert!r}, "
            f"http1={self.http1}, http2={self.http2}, proxy={self.proxy!r}, "
            f"timeout={self.timeout!r}, follow_redirects={self.follow_redirects}, "
            f"limits={self.limits!r}, max_redirects={self.max_redirects}, "
            f"event_hooks={self.event_hooks!r}, base_url={self.base_url!r}, "
            f"transport={self.transport!r}, trust_env={self.trust_env}, "
            f"default_encoding={self.default_encoding!r})"
        )

    def __str__(self) -> str:
        return f"<ClientSettings base_url={self.base_url!r} http1={self.http1} http2={self.http2}>"
